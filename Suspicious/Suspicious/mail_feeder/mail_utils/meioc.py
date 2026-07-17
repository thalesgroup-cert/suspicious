#!/usr/bin/env python3
import os
            
import re
from urllib.parse import urlparse
import spf
import json
import dkim
import hashlib
import warnings
import argparse
import ipaddress
import logging
import encodings
import tldextract
from pathlib import Path
from email import policy
from bs4 import BeautifulSoup
from email.utils import parseaddr
from email import message_from_bytes

encodings.aliases.aliases["cp_850"] = "cp850"
warnings.simplefilter(action="ignore", category=FutureWarning)

email_regex = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
PSL_FILE = (
    Path(__file__).resolve().parents[2]
    / "domain_process" / "domain_utils" / "public" / "public_suffix_list.dat"
)
HASH_PATTERNS = [
    r'\b[a-f0-9]{32}\b',
    r'\b[a-f0-9]{40}\b',
    r'\b[a-f0-9]{64}\b'
]
tldcache = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(PSL_FILE.as_uri(),) if PSL_FILE.is_file() else (),
    fallback_to_snapshot=True,
)
fetch_mail_logger = logging.getLogger('tasp.cron.fetch_and_process_emails')

def real_email(string):
    result_meioc = None
    try:
        _, email_address = parseaddr(string)
        return email_address.lower() if email_address else None
    except (AttributeError, ValueError, TypeError) as exc:
        fetch_mail_logger.warning("real_email parseaddr failed for %r: %s", string, exc)
        return result_meioc

def normalize_headers(raw_email_bytes):
    """
    Normalize email headers by fixing spaces before ':' in a bytes-like email,
    while preserving multi-line header continuation.
    
    Args:
        raw_email_bytes (bytes): Raw email in bytes-like format.
    Returns:
        bytes: Normalized email in bytes-like format.
    """

    raw_email = raw_email_bytes.decode("utf-8", errors="replace")
    
    lines = raw_email.splitlines()
    normalized_lines = []
    for i, line in enumerate(lines):
        if line.startswith((' ', '\t')):
            normalized_lines.append(line)
        else:
            if ": " in line or ":" in line:
                header, _, value = line.partition(":")
                header = header.strip()
                normalized_lines.append(f"{header}:{value}")
            else:
                normalized_lines.append(line)
    
    normalized_email = "\n".join(normalized_lines)
    return normalized_email.encode("utf-8")

def email_analysis(filename, exclude_private_ip, check_spf, check_dkim, file_output):
    urls_list = []
    body_Hash = []
    hops_list = []
    hops_list_ip = []
    domains_list = []
    attachments_ist = []
    hops_list_ip_public = []
    body_IP = []
    body_email = []
    
    result_meioc = {
        "filename": os.path.basename(filename),
        "from": None,
        "sender": None,
        "x-sender": None,
        "to": None,
        "cc": None,
        "bcc": None,
        "envelope-to": None,
        "delivered-to": None,
        "return-path": None,
        "subject": None,
        "date": None,
        "user-agent": None,
        "x-mailer": None,
        "x-originating-ip": None,
        "relay_full": None,
        "relay_ip": None,
        "body_ip": None,
        "body_hash": None,
        "body_email": None,
        "spf": None,
        "dkim": None,
        "urls": None,
        "domains": None,
        "attachments": None
    }

    fetch_mail_logger.debug(f"Processing email file: {filename}")
    with open(filename, "rb") as email_file:
        raw_email_content = email_file.read()

    fetch_mail_logger.debug(f"Raw email content read from file: {filename}")
    try:
        if raw_email_content:
            raw_email_content_normalized = normalize_headers(raw_email_content)
            parsed_email = message_from_bytes(raw_email_content_normalized, policy=policy.default)
            fetch_mail_logger.debug(f"Email parsed successfully from file: {filename}")
        else:
            fetch_mail_logger.error(f"Failed to read email content from file: {filename}")
            return result_meioc
    except Exception as e:
        fetch_mail_logger.error(f"Failed to parse email from file {filename}: {e}")
        return result_meioc
    if parsed_email:
        fetch_mail_logger.debug(f"Email parsed successfully: {parsed_email.get('Subject', 'No Subject')}")
        try:
            if parsed_email["Date"]:
                result_meioc["date"] = parsed_email["Date"]

            if parsed_email["From"]:
                mail_from = real_email(parsed_email["From"])

                if mail_from:
                    result_meioc["from"] = mail_from

            if parsed_email["Sender"]:
                mail_sender = real_email(parsed_email["Sender"])

                if mail_sender:
                    result_meioc["sender"] = mail_sender

            if parsed_email["X-Sender"]:
                mail_xsender = real_email(parsed_email["X-Sender"])

                if mail_xsender:
                    result_meioc["x-sender"] = mail_xsender

            if parsed_email["To"]:
                mail_to = email_regex.findall(parsed_email["To"])
                if mail_to:
                    mail_to = {i: x.lower() for i, x in enumerate(set(mail_to))}
                    result_meioc["to"] = mail_to

            if parsed_email["Bcc"]:
                result_meioc["bcc"] = parsed_email["Bcc"].lower()

            if parsed_email["Cc"]:
                mail_cc_list = []
                for mail in parsed_email["Cc"].split(","):
                    mail_cc = real_email(mail)

                    if mail_cc:
                        mail_cc_list.append(mail_cc)

                if mail_cc_list:
                    mail_cc_list = {i: x.lower() for i, x in enumerate(set(mail_cc_list))}
                    result_meioc["cc"] = mail_cc_list


            if parsed_email["Message-ID"]:
                result_meioc["message-id"] = parsed_email["Message-ID"]

            if parsed_email["Reply-To"]:
                result_meioc["reply-to"] = re.findall(r"[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", parsed_email["Reply-To"][0],
                                    re.IGNORECASE)
            if parsed_email["Envelope-to"]:

                mail_envelopeto = email_regex.findall(parsed_email["Envelope-to"])

                if mail_envelopeto:
                    mail_envelopeto = {i: x.lower() for i, x in enumerate(set(mail_envelopeto))}
                    result_meioc["envelope-to"] = mail_envelopeto

            if parsed_email["Delivered-To"]:
                result_meioc["delivered-to"] = parsed_email["Delivered-To"].lower()

            if parsed_email["Return-Path"]:
                mail_returnpath = real_email(parsed_email["Return-Path"])

                if mail_returnpath:
                    result_meioc["return-path"] = mail_returnpath

            if parsed_email["User-Agent"]:
                result_meioc["user-agent"] = parsed_email["User-Agent"]

            if parsed_email["X-Mailer"]:
                result_meioc["x-mailer"] = parsed_email["X-Mailer"]

            if parsed_email["X-Originating-IP"]:
                mail_xorigip = parsed_email["X-Originating-IP"].replace("[", "").replace("]", "")
                result_meioc["x-originating-ip"] = mail_xorigip

            if parsed_email["Subject"]:
                result_meioc["subject"] = parsed_email["Subject"]
            fetch_mail_logger.debug("Identifying relays in email headers")
            received = parsed_email.get_all("Received")
            if received:
                received.reverse()
                for line in received:
                    hops = re.findall(r"from\s+(.*?)\s+by(.*?)(?:(?:with|via)(.*?)(?:id|$)|id|$)", line, re.DOTALL | re.X)
                    for hop in hops:
                        ipv4_address = re.findall(r"[0-9]+(?:\.[0-9]+){3}", hop[0], re.DOTALL | re.X)

                        ipv6_address = re.findall(
                            r"(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}:[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:fe80:(?::(?:(?:[0-9a-fA-F]){1,4})){0,4}%[0-9a-zA-Z]{1,})|(?::(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,7}|:))|(?:(?:(?:[0-9a-fA-F]){1,4}):(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,6}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,2}(?::(?:(?:[0-9a-fA-F]){1,4})){1,5})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,3}(?::(?:(?:[0-9a-fA-F]){1,4})){1,4})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}(?::(?:(?:[0-9a-fA-F]){1,4})){1,3})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,5}(?::(?:(?:[0-9a-fA-F]){1,4})){1,2})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,6}:(?:(?:[0-9a-fA-F]){1,4}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,7}:)|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){7,7}(?:(?:[0-9a-fA-F]){1,4}))",
                            hop[0], re.DOTALL | re.X)

                        if ipv4_address:
                            for ipv4 in ipv4_address:
                                if ipaddress.ip_address(ipv4):
                                    hops_list_ip.append(ipv4)
                                    if not ipaddress.ip_address(ipv4).is_private:
                                        hops_list_ip_public.append(ipv4)

                        if ipv6_address:
                            for ipv6 in ipv6_address:
                                if ipaddress.ip_address(ipv6) and not "6::":
                                    hops_list_ip.append(ipv6)

                                    if not ipaddress.ip_address(ipv6).is_private:
                                        hops_list_ip_public.append(ipv6)

                        if hop[0]:
                            hops_list.append(hop[0])

            if hops_list:
                result_meioc["relay_full"] = dict(zip(range(len(hops_list)), hops_list))

            if hops_list_ip:
                if exclude_private_ip:
                    result_meioc["relay_ip"] = dict(zip(range(len(hops_list_ip_public)), hops_list_ip_public))
                else:
                    result_meioc["relay_ip"] = dict(zip(range(len(hops_list_ip)), hops_list_ip))
        except Exception as e:
            fetch_mail_logger.error(f"Error processing email headers: {e}")
            return result_meioc
        fetch_mail_logger.debug("Header analysis completed successfully")
        try:
            fetch_mail_logger.debug("Extracting URLs, IPs, emails, and hashes from email body")

            candidates = []
            for part in parsed_email.walk():

                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                text = payload.decode('utf-8', errors='ignore')

                if part.get_content_type() == "text/plain":
                    candidates.extend(re.findall(r'(?:https?://|www\.)[^\s<>"]+', text))
                    body_IP.extend(re.findall(r"[0-9]+(?:\.[0-9]+){3}", str(part.get_payload()), re.DOTALL | re.X))

                    body_email.extend(re.findall(r"[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", part.get_content(),
                                    re.IGNORECASE))

                    for pattern in HASH_PATTERNS:
                        body_Hash.extend(re.findall(pattern, part.get_content(), re.IGNORECASE))

                if part.get_content_type() == "text/html":
                    try:
                        soup = BeautifulSoup(text, 'html.parser')
                        for a in soup.find_all('a', href=True):
                            candidates.append(a['href'])
                        body_IP.extend(re.findall(r"[0-9]+(?:\.[0-9]+){3}", str(part.get_payload()), re.DOTALL | re.X))

                        body_email.extend(re.findall(r"[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", part.get_content(),
                            re.IGNORECASE))
                        for pattern in HASH_PATTERNS:
                            body_Hash.extend(re.findall(pattern, part.get_content(), re.IGNORECASE))
                    except (TypeError, ValueError, UnicodeDecodeError, LookupError) as exc:
                        fetch_mail_logger.warning("Body IOC extraction skipped (%s)", exc)

                if part.get_filename():
                    if part.get_payload(decode=True):
                        filename = part.get_filename()
                        filemd5 = hashlib.md5(part.get_payload(decode=True)).hexdigest()
                        filesha1 = hashlib.sha1(part.get_payload(decode=True)).hexdigest()
                        filesha256 = hashlib.sha256(part.get_payload(decode=True)).hexdigest()

                        attachments_ist.append({"filename": filename, "MD5": filemd5, "SHA1": filesha1,
                                                "SHA256": filesha256})

            seen = set()
            for url in candidates:
                url = url.rstrip('.,;:')
                lower = url.lower()
                if lower.startswith('mailto:') or lower.startswith('ftp:'):
                    continue
                if not lower.startswith(('http://','https://')):
                    url = 'http://' + url
                parsed = urlparse(url)
                host = parsed.hostname or ''
                if host.replace('.', '').isdigit() or ':' in host:
                    continue
                clean = parsed.geturl()
                if clean not in seen:
                    seen.add(clean)
                    urls_list.append(clean)
        except Exception as e:
            fetch_mail_logger.error(f"Error processing email body: {e}")
            return result_meioc
        
        fetch_mail_logger.debug("Body analysis completed successfully")
        
        try:
            for url in urls_list:
                analyzed_domain = tldcache(url).registered_domain
                if analyzed_domain:
                    domains_list.append(analyzed_domain)
        except Exception as e:
            fetch_mail_logger.error(f"Error processing email domains: {e}")
            return result_meioc
        urls_list = list(set(urls_list))
        domains_list = list(set(domains_list))

        if urls_list:
            result_meioc["urls"] = dict(zip(range(len(urls_list)), urls_list))
            result_meioc["domains"] = dict(zip(range(len(domains_list)), domains_list))

        if attachments_ist:
            result_meioc["attachments"] = attachments_ist

        if body_IP:
            result_meioc["body_ip"] = body_IP
        if body_Hash:
            result_meioc["body_hash"] = body_Hash
        if body_email:
            result_meioc["body_email"] = body_email
            
        fetch_mail_logger.debug("Email analysis completed successfully")
        fetch_mail_logger.debug("Checking SPF records if requested")
        if check_spf:
            try:
                fetch_mail_logger.debug("Checking SPF records for the email")
                test_spf = False
                resultspf = ""
                for ip in hops_list_ip_public:
                    if not test_spf and "mail_from" in locals():
                        try:
                            domain_from = mail_from.split("@")[1]
                            result_spf = spf.check2(ip, mail_from,domain_from)[0]
                        except (IndexError, AttributeError, TypeError, ValueError) as exc:
                            fetch_mail_logger.warning(
                                "SPF check skipped for ip=%s mail_from=%r: %s",
                                ip, mail_from, exc,
                            )

                        if result_spf == "pass":
                            test_spf = True
                        else:
                            test_spf = False

                result_meioc["spf"] = test_spf
            except Exception as e:
                fetch_mail_logger.error(f"Error checking SPF record: {e}")
                result_meioc["spf"] = None
        fetch_mail_logger.debug("SPF record check completed")
        fetch_mail_logger.debug("Checking DKIM records if requested")
        if check_dkim:
            test_dkim = False
            try:
                dkim_result = dkim.verify(raw_email_content_normalized)
                if dkim_result:
                    test_dkim = True
            except Exception as e:
                fetch_mail_logger.error(f"Error checking DKIM record: {e}")
                test_dkim = False

            result_meioc["dkim"] = test_dkim

        fetch_mail_logger.debug("DKIM record check completed")
        
        if file_output:
            with open(file_output, "w") as f:
                json.dump(result_meioc, f, indent=4)
            print("[!] Output saved in: %s" % file_output)
        else:
            try:
                fetch_mail_logger.debug("Returning JSON result")
                result = json.dumps(result_meioc, indent=4)
                return result
            except (TypeError, ValueError) as exc:
                fetch_mail_logger.error("meioc result JSON serialise failed: %s", exc)
                return None
            


def main():
    version = "1.4"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Analyze an e-mail (.eml format)")
    parser.add_argument("-x", "--exclude-private-ip", action="store_true", dest="excprip",
                        help="Exclude private IPs from the report")
    parser.add_argument("-s", "--spf", action="store_true", dest="spf",
                        help="Check SPF Records")
    parser.add_argument("-d", "--dkim", action="store_true", dest="dkim",
                        help="Check DKIM Records")
    parser.add_argument("-o", "--output", dest="file_output",
                        help="Write output to <file>")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + version)

    arguments = parser.parse_args()

    if arguments.filename:
        email_analysis(arguments.filename, arguments.excprip, arguments.spf ,arguments.dkim, arguments.file_output)


if __name__ == "__main__":
    main()