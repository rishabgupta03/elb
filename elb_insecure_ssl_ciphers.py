
#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError, BotoCoreError

CONTROL_NAME = "ELB HTTPS Listeners Use ELBSecurityPolicy-TLS-1-2-2017-01"

REQUIRED_POLICY = "ELBSecurityPolicy-TLS-1-2-2017-01"
SECURE_PROTOCOLS = ("HTTPS", "SSL")

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=True)["Regions"]

    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    """
    Maps a boto3/botocore exception to (status, evidence).
    One small function instead of a long if/else chain repeated
    throughout the control logic.
    """
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "UnknownError")

        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "SKIPPED", f"Access denied while querying ELB ({code})"

        if code in ("Throttling", "ThrottlingException"):
            return "SKIPPED", f"Throttled by AWS API ({code})"

        if code == "LoadBalancerNotFound":
            return "SKIPPED", "Load balancer no longer exists"

        return "SKIPPED", f"Could not evaluate resource: {code}"

    if isinstance(e, BotoCoreError):
        return "SKIPPED", f"Could not reach ELB endpoint: {e}"

    return "SKIPPED", f"Unexpected error: {e}"


def get_insecure_https_ports(listener_descriptions):
    """
    Returns the list of HTTPS/SSL listener ports that are NOT using the
    required ELBSecurityPolicy-TLS-1-2-2017-01 policy. An empty list
    combined with at least one HTTPS/SSL listener means compliant.
    """
    insecure_ports = []

    for ld in listener_descriptions:
        listener = ld.get("Listener", {})
        protocol = listener.get("Protocol", "")

        if protocol in SECURE_PROTOCOLS:
            policy_names = ld.get("PolicyNames", [])
            if REQUIRED_POLICY not in policy_names:
                insecure_ports.append(listener.get("LoadBalancerPort"))

    return insecure_ports


def has_https_listener(listener_descriptions):
    return any(
        ld.get("Listener", {}).get("Protocol", "") in SECURE_PROTOCOLS
        for ld in listener_descriptions
    )


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_control(session):

    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            client = session.client("elb", region_name=region)

        except (ClientError, BotoCoreError) as e:
            status, evidence = classify_error(e)
            skipped += 1
            results.append({
                "Account": account_id,
                "Region": region,
                "ResourceId": "N/A",
                "ResourceArn": "N/A",
                "Status": status,
                "Evidence": evidence
            })
            continue

        try:
            paginator = client.get_paginator("describe_load_balancers")

            for page in paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):

                    lb_name = lb.get("LoadBalancerName", "N/A")
                    lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb_name}"
                    listener_descriptions = lb.get("ListenerDescriptions", [])

                    total_checked += 1

                    if not has_https_listener(listener_descriptions):
                        status = "SKIPPED"
                        skipped += 1
                        evidence = "No HTTPS/SSL listeners configured, control not applicable"
                    else:
                        insecure_ports = get_insecure_https_ports(listener_descriptions)

                        if insecure_ports:
                            status = "NON_COMPLIANT"
                            non_compliant += 1
                            evidence = (
                                f"HTTPS/SSL listener(s) on port(s) {insecure_ports} "
                                f"not using {REQUIRED_POLICY}"
                            )
                        else:
                            status = "COMPLIANT"
                            compliant += 1
                            evidence = f"All HTTPS/SSL listeners use {REQUIRED_POLICY}"

                    results.append({
                        "Account": account_id,
                        "Region": region,
                        "ResourceId": lb_name,
                        "ResourceArn": lb_arn,
                        "Status": status,
                        "Evidence": evidence
                    })

        except (ClientError, BotoCoreError) as e:
            status, evidence = classify_error(e)
            skipped += 1
            results.append({
                "Account": account_id,
                "Region": region,
                "ResourceId": "N/A",
                "ResourceArn": "N/A",
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================

def write_csv(results, account_id):
    filename = f"elb_insecure_ssl_ciphers_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        writer.writerows(results)

    return filename


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check whether ELB HTTPS/SSL listeners use the ELBSecurityPolicy-TLS-1-2-2017-01 policy."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 52)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 52)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Generated   : {csv_file}")
    print("=" * 52 + "\n")


if __name__ == "__main__":
    main()
