from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List
from fastapi.security import OAuth2PasswordBearer
from .config import Settings
from loguru import logger

import subprocess
import requests
import json
import socket
import sys
import re
import urllib3
import os
import hashlib
import uuid
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log_file = os.path.join(os.path.dirname(__file__), "logs", "easm_worker_v2.log")
logger.remove()
logger.add(sink=log_file, level="INFO")
logger.add(sink=sys.stderr, level="INFO")


# Based on https://testdriven.io/tips/6840e037-4b8f-4354-a9af-6863fb1c69eb/
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # use token authentication


def api_key_auth(api_key: str = Depends(oauth2_scheme)):
    if api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Forbidden"
        )


def filter_dict(input_dict, fields_to_keep):
    return {field: input_dict[field] for field in fields_to_keep if field in input_dict}


HOST = socket.gethostname()
if not os.getenv("API_KEY") and not os.path.isfile(".env"):
    logger.error(
        "Please ensure you have environment variable API_KEY, or a .env file for it."
    )
    sys.exit(1)
settings = Settings()
app = FastAPI()


class DiscoveryParams(BaseModel):
    entity: str
    callback_url: str
    callback_auth: str | None = None
    callback_verify: bool = True
    target_list: List[str]
    take_screenshots: bool = False


def contains_special_characters(strings_list):
    special_characters = {";", "|", "&"}
    return [
        string
        for string in strings_list
        if any(char in special_characters for char in string)
    ]


def resolve_names(targets: List[str]):
    process_args = ["dnsx", "-json", "-silent"]
    targets_to_resolve = []
    all_ips = []

    for target in targets:
        if not re.match(pattern=r"(\d+\.\d+\.\d+\.\d+)|.*:.*", string=target):
            targets_to_resolve.append(target)
        else:
            all_ips.append(target)

    result = subprocess.run(
        process_args,
        capture_output=True,
        text=True,
        input=("\n".join(targets_to_resolve)),
    )

    try:
        objects = [json.loads(line) for line in result.stdout.strip().splitlines()]
    except Exception as e:
        logger.error(str(e))
        return

    # Note that even if the DNS record is a cname,
    # uncover will give us the a records for that cname
    objects_with_a_records = [o for o in objects if "a" in o]
    ip_to_hosts = {value: o["host"] for o in objects_with_a_records for value in o["a"]}
    all_ips += ip_to_hosts.keys()
    return ip_to_hosts, all_ips


def post_to_hec(url, token, json_payload, sourcetype, source, verify):
    """
    send to HEC - JSON-formatted rather than raw
    this means the url should end with `/services/collector/event`
    rather than '.../_raw'
    it means our payload must be inside of an "event" field and we can provide metadata
    """
    headers = {"Authorization": token}

    response = requests.post(
        url=url,
        headers=headers,
        json={
            "event": json_payload,
            "sourcetype": sourcetype,
            "source": source,
            "host": HOST,
        },
        verify=verify,
    )

    return response.status_code


def do_discovery(
    entity,
    process_args,
    target_list,
    sourcetype,
    callback_url,
    callback_auth,
    callback_verify,
):
    logger.info(
        "entity: {}, tool: {}, len(target_list): {}",
        entity,
        process_args[0],
        len(target_list),
    )

    uid = str(uuid.uuid4())

    if len(contains_special_characters(target_list)) > 0:
        # Quitting to avoid command injection
        return

    # Build an ip->hostname mapping if we need to do passive port discovery
    # We'll later use this to stamp results with the original hostname
    resolved_names = []
    if process_args[0] == "uncover":
        resolved_names, all_ips = resolve_names(target_list)
        target_list = list(set(all_ips))

    # Old approach - send lists in as stdin,
    # which didn't seem to work well for httpx -screenshot
    # result = subprocess.run(
    #     process_args,
    #     capture_output=True,
    #     text=True,
    #     input=("\n".join(target_list)),
    # )

    status_code = None

    for target in target_list:
        result = subprocess.run(
            process_args,
            capture_output=True,
            text=True,
            input=target,
        )

        # Parse the lines of text output into json objects
        objects = []
        if process_args[0] == "uncover":
            # uncover -json isn't working so let's convert the
            # semicolon-delimited output to json
            header = ["ip", "port", "hostname"]
            objects = [
                dict(zip(header, line.split(":")))
                for line in result.stdout.strip().splitlines()
            ]
            # consolidate all the hostnames
            # if len(objects):
            #     objects = [
            #         {
            #             "ip": objects[0]["ip"],
            #             "port": objects[0]["port"],
            #             "hostname": ",".join([o["hostname"] for o in objects]),
            #         }
            #     ]

            # Dictionary to consolidate values by ip and port
            consolidated_dict = {}

            for obj in objects:
                key = (obj["ip"], obj["port"])
                if key not in consolidated_dict:
                    consolidated_dict[key] = {
                        "ip": obj["ip"],
                        "port": obj["port"],
                        "hostnames": [],
                    }
                consolidated_dict[key]["hostnames"].append(obj["hostname"])

            # Creating the objects_consolidated list
            objects_consolidated = [
                {
                    "ip": data["ip"],
                    "port": data["port"],
                    "hostname": ", ".join(data["hostnames"]),
                }
                for data in consolidated_dict.values()
            ]
            objects = objects_consolidated
        else:
            # parse as json
            try:
                objects = [
                    json.loads(line) for line in result.stdout.strip().splitlines()
                ]
            except Exception as e:
                logger.error(str(e))
                logger.error(
                    "len of stdout is :" + str(result.stdout.strip().splitlines())
                )
                logger.error(str(result.stdout.strip().splitlines()))
                return

        logger.info(
            (
                f"Posting {len(objects)} objects to HEC."
                f"Sourcetype: {sourcetype}. Target: {target}"
            )
        )

        for o in objects:
            o["easm"] = {
                "entity": entity,
                "target": target,
                "scan_id": uid,
                "scan_time": datetime.datetime.utcnow().strftime("%s"),
            }

            if process_args[0] == "uncover":
                if o["ip"] in resolved_names:
                    o["easm"]["hostname"] = resolved_names[o["ip"]]

            if process_args[0] == "nuclei":
                nuclei_subset_fields = [
                    "template-id",
                    "type",
                    "host",
                    "matched-at",
                    "matcher-name",
                    "type",
                    "ip",
                    "timestamp",
                    "extracted-results",
                    "info",
                    "easm",
                ]
                o = filter_dict(o, nuclei_subset_fields)

            if "host" in o:
                o["hostname"] = o.pop("host")

            if "source" in o:
                o["discovery_source"] = o.pop("source")

            if "time" in o:
                o["time"] = re.sub(pattern="ms$", repl="", string=o["time"])
                if o["time"].endswith("s"):
                    o["time"] = str(float(o["time"].replace("s", "")) * 1000)
                o["time"] = str(round(float(o["time"]), 2))

            if "stored_response_path" in o:
                o.pop("stored_response_path")

            if process_args[0] == "naabu":
                o["port"] = o["port"]["Port"]
                o["easm"]["hostname"] = o.pop("hostname")
                # if process_args[1] == "-passive":
                #     o["easm"]["port_scan_type"] = "passive"
                # else:
                #     o["easm"]["port_scan_type"] = "active"
            # legacy passive port scan using uncover
            elif process_args[0] == "uncover":
                o["easm"]["port_scan_type"] = "passive"

            if process_args[0] == "katana":
                if "response" in o and "body" in o["response"]:
                    o["response"]["body_length"] = len(o["response"]["body"])
                    o["response"]["body_md5"] = hashlib.md5(
                        o["response"].pop("body").encode("utf-8")
                    ).hexdigest()

            status_code = post_to_hec(
                url=callback_url,
                token=callback_auth,
                sourcetype=sourcetype,
                source=process_args[0],
                json_payload=o,
                verify=callback_verify,
            )

        # logger.info(f"Final status_code from posting to HEC: {status_code}")
    logger.info(f"Done posting to HEC. Most recent status code: {status_code}")


@app.post("/discovery/subdomains/", dependencies=[Depends(api_key_auth)])
async def sub_discovery(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=[
            "subfinder",
            "-silent",
            "-json",
            "-active",
            "-ip",
            "-timeout",
            "10",
        ],
        target_list=discovery_params.target_list,
        sourcetype="easm:subdomain",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Subdomain discovery task initiated"}


@app.post("/discovery/open_ports/", dependencies=[Depends(api_key_auth)])
async def openport_passive_discovery(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=["uncover", "-e", "shodan-idb", "-silent"]
        + ["-f", "ip:port:host"],
        target_list=discovery_params.target_list,
        sourcetype="easm:open_port",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Passive open port discovery task initiated"}


# @app.post("/discovery/open_ports_EXPERIMENT/", dependencies=[Depends(api_key_auth)])
# async def openport_passive_discovery_v2(
#     discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
# ):
#     background_tasks.add_task(
#         do_discovery,
#         entity=discovery_params.entity,
#         process_args=["naabu", "-passive", "-silent", "-json"],
#         target_list=discovery_params.target_list,
#         sourcetype="easm:open_port",
#         callback_url=discovery_params.callback_url,
#         callback_auth=discovery_params.callback_auth,
#         callback_verify=discovery_params.callback_verify,
#     )
#     return {"message": "Passive open port discovery task initiated"}


@app.post("/discovery/open_ports_scan/", dependencies=[Depends(api_key_auth)])
async def openport_active_discovery(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=["naabu", "-silent", "-json"],
        target_list=discovery_params.target_list,
        sourcetype="easm:open_port",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Active open port discovery task initiated"}


@app.post("/discovery/http_services/", dependencies=[Depends(api_key_auth)])
async def http_discovery(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    process_args = [
        "httpx",
        "-json",
        "-tech-detect",
        "-silent",
        "-favicon",
        "-timeout",
        "15",
    ]

    if discovery_params.take_screenshots:
        process_args.extend(["-screenshot", "-system-chrome"])

    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=process_args,
        target_list=discovery_params.target_list,
        sourcetype="easm:http_service",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    logger.debug(f"Target list: {discovery_params.target_list}")
    return {"message": "HTTP service discovery task initiated"}


@app.post("/discovery/dns_records/", dependencies=[Depends(api_key_auth)])
async def dns_discovery(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=["dnsx", "-json", "-silent"],
        target_list=discovery_params.target_list,
        sourcetype="easm:dns_records",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "DNS resolution task initiated"}


@app.post("/discovery/tls_certs/", dependencies=[Depends(api_key_auth)])
async def cert_parse(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=["tlsx", "-json", "-silent"],
        target_list=discovery_params.target_list,
        sourcetype="easm:tls_cert",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "TLS cert parse task initiated"}


@app.post("/discovery/web_tech/", dependencies=[Depends(api_key_auth)])
async def web_tech_scan(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=[
            "nuclei",
            "-jsonl",
            "-silent",
            "-or",
            "-id",
            (
                "metatag-cms,ssl-dns-names,waf-detect,ssl-issuer,"
                "http-missing-security-headers,tls-version,tech-detect"
                ",dns-waf-detect,azure-domain-tenant,mx-service-detector,ms-fingerprint"
                ",wordpress-detect,robots-txt-endpoint,s3-detect"
            ),
        ],
        target_list=discovery_params.target_list,
        sourcetype="easm:web_tech_scan",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Web tech scan task initiated"}


@app.post("/discovery/web_vuln_scan/", dependencies=[Depends(api_key_auth)])
async def web_vuln_scan(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=[
            "nuclei",
            "-jsonl",
            "-silent",
            "-or",
        ],
        target_list=discovery_params.target_list,
        sourcetype="easm:web_vuln_scan",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Web vuln scan task initiated"}


@app.post("/discovery/web_spider/", dependencies=[Depends(api_key_auth)])
async def web_spider(
    discovery_params: DiscoveryParams, background_tasks: BackgroundTasks
):
    background_tasks.add_task(
        do_discovery,
        entity=discovery_params.entity,
        process_args=["katana", "-jsonl", "-silent", "-or"],
        target_list=discovery_params.target_list,
        sourcetype="easm:web_spider",
        callback_url=discovery_params.callback_url,
        callback_auth=discovery_params.callback_auth,
        callback_verify=discovery_params.callback_verify,
    )
    return {"message": "Web spider task initiated"}
