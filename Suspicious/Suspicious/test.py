import os
import django
import json
import logging
from minio import Minio
from minio.error import S3Error

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

minio_config = config.get("minio", {})

# Set up Django environment
# mettre cette ligne avant
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'suspicious.settings')
django.setup()

# permet d'appeler les models django
from case_handler.models import Case
from mail_feeder.models import Mail

output_folder = "challenged_mails"
os.makedirs(output_folder, exist_ok=True)

cases = Case.objects.filter(is_challenged=True)
for case in cases:
    mail_id = str(case.fileOrMail.mail.mail_id)
    update_cases_logger.info(f"Mail id for case {case.id}: {mail_id}")

    eml = ''
    txt = ''
    headers = ''
    html = ''
    minio_client = Minio(
        minio_config.get("endpoint"),
        access_key=minio_config.get("access_key"),
        secret_key=minio_config.get("secret_key"),
        secure=False
    )
    for bucket in minio_client.list_buckets():
        if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
            try:
                objects = minio_client.list_objects(bucket.name, prefix=mail_id, recursive=False)
                for obj in objects:
                    update_cases_logger.info(f"Checking object: {obj.object_name} in bucket: {bucket.name}")
                    # if obj.object_name.startswith(mail_id):
                    #     expected_headers_key = f"{mail_id}/{mail_id}.headers"
                    #     data = minio_client.get_object(bucket.name, expected_headers_key)
                    #     headers = data.read().decode('utf-8')
                    #     update_cases_logger.info(f"Found .headers file in bucket: {bucket.name}")

                    # ici on veut que le suspects

                    if obj.object_name.startswith(mail_id):
                        expected_eml_key = f"{mail_id}/{mail_id}.eml"
                        data = minio_client.get_object(bucket.name, expected_eml_key)
                        eml = data.read().decode('utf-8')
                        update_cases_logger.info(f"Found .eml file in bucket: {bucket.name}")
                    # if obj.object_name.startswith(mail_id):
                    #     expected_txt_key = f"{mail_id}/{mail_id}.txt"
                    #     data = minio_client.get_object(bucket.name, expected_txt_key)
                    #     txt = data.read().decode('utf-8')
                    #     update_cases_logger.info(f"Found .txt file in bucket: {bucket.name}")
                    # if obj.object_name.startswith(mail_id):
                    #     expected_html_key = f"{mail_id}/{mail_id}.html"
                    #     data = minio_client.get_object(bucket.name, expected_html_key)
                    #     html = data.read().decode('utf-8')
                    #     update_cases_logger.info(f"Found .html file in bucket: {bucket.name}")

                        mail_folder = os.path.join(OUTPUT_DIR, mail_id)
                        os.makedirs(mail_folder, exist_ok=True)

                        file_path = os.path.join(mail_folder, f"{mail_id}.eml")
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(eml)
            except S3Error as e:
                update_cases_logger.error(f"Error listing objects in bucket {bucket.name}: {e}")
    