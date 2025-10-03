from django.http import JsonResponse
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from file_process.models import File
from case_handler.models import Case
from case_handler.update_case.update_case import update_ioc_level_and_cases
import logging
from django.apps import apps
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def get_attachments_and_artifacts(case):
    """Get attachments and artifacts for a given case.

    This function retrieves the attachments and artifacts associated with a given case.

    Args:
        case (Case): The case object for which to retrieve attachments and artifacts.

    Returns:
        tuple: A tuple containing two lists - attachments and artifacts.
               The attachments list contains all the attachments associated with the case.
               The artifacts list contains all the artifacts associated with the case,
               excluding artifacts of type 'Domain' and 'MailAddress'.
    """
    attachments = []
    artifacts = []
    if case.fileOrMail and case.fileOrMail.mail:
        attachments = case.fileOrMail.mail.mail_attachments.all()
        artifacts = case.fileOrMail.mail.mail_artifacts.exclude(artifact_type__in=['Domain', 'MailAddress'])
    return attachments, artifacts

def handle_attachment(id, level, case_id):
    """Handles the attachment by updating the IOC level and cases.

    Args:
        id (int): The ID of the attachment.
        level (str): The level of the IOC.
        case_id (int): The ID of the case.

    Returns:
        dict: A JSON response containing the success status, scores, levels, and case information.
    """
    file = File.objects.filter(linked_hash__value=id).first()
    if file:
        # Update the file and its linked hash (handled within update_ioc_level_and_cases)
        obj = update_ioc_level_and_cases(file, "file", level)
        obj_score = obj.file_score
        obj_confidence = obj.file_confidence
        obj_level = obj.file_level

        # Get the linked hash information directly from the updated file object
        linked_hash = file.linked_hash
        hash_obj_score = linked_hash.ioc_score
        hash_obj_confidence = linked_hash.ioc_confidence
        hash_obj_level = linked_hash.ioc_level

        case = Case.objects.get(id=case_id)
        case_infos = {
            "id": case.id,
            "score": case.finalScore,
            "confidence": case.finalConfidence,
            "results": case.results,
        }
        update_cases_logger.info(f"Case updated with id {case.id}, score {case.finalScore}, confidence {case.finalConfidence}, and results {case.results}")
        return JsonResponse({'success': True, 'score': obj_score, 'confidence': obj_confidence, 'level': obj_level, 'hash_score': hash_obj_score, 'hash_confidence': hash_obj_confidence, 'hash_level': hash_obj_level, 'case_infos': case_infos})
    else:
        update_cases_logger.error(f"File with linked hash {id} not found")
        return JsonResponse({'success': False, 'error': 'File does not exist'})

def handle_artifact(id, level, case_id):
    """Handles the artifact with the given ID, updates its IOC level and cases,
    and returns the artifact's score, confidence, level, and case information.

    Args:
        id (int): The ID of the artifact.
        level (str): The IOC level to update.
        case_id (int): The ID of the case.

    Returns:
        dict: A dictionary containing the following keys:
            - 'success' (bool): Indicates whether the operation was successful.
            - 'score' (float): The artifact's IOC score.
            - 'confidence' (float): The artifact's IOC confidence.
            - 'level' (str): The artifact's updated IOC level.
            - 'case_infos' (dict): A dictionary containing the following keys:
                - 'id' (int): The ID of the case.
                - 'score' (float): The case's final score.
                - 'confidence' (float): The case's final confidence.
                - 'results' (str): The case's results.

    Raises:
        None.
    """
    artifact = get_artifact_by_id(id)
    artifact_type = artifact.__class__.__name__.lower() if artifact else None
    if artifact:
        print(f"Artifact with id {artifact.id} found")
        update_ioc_level_and_cases(artifact, artifact_type, level)
        obj_score = artifact.ioc_score
        obj_confidence = artifact.ioc_confidence
        obj_level = artifact.ioc_level

        case = Case.objects.get(id=case_id)
        case_infos = {
            "id": case.id,
            "score": case.finalScore,
            "confidence": case.finalConfidence,
            "results": case.results,
        }
        print(f"Case updated with id {case.id}, score {case.finalScore}, confidence {case.finalConfidence}, and results {case.results}")
        return JsonResponse({'success': True, 'score': obj_score, 'confidence': obj_confidence, 'level': obj_level, 'case_infos': case_infos})
    else:
        print(f"Artifact with id {id} not found")
        return JsonResponse({'success': False, 'error': 'Artifact does not exist'})

def handle_mail(ioc_id: int, mail_type: str, level: int, case_id: int) -> JsonResponse:
    """
    Handle mail IOC update for type 'body' or 'header'.
    """
    if mail_type not in {"body", "header"}:
        return JsonResponse({"success": False, "error": "Invalid mail_type"}, status=400)

    model_name = f"Mail{mail_type.capitalize()}"
    try:
        mail_model = apps.get_model("mail_feeder", model_name)  # <-- adapter "your_app_name"
    except LookupError:
        print(f"Model {model_name} not found in app 'your_app_name'")
        return JsonResponse({"success": False, "error": "Mail model not found"}, status=500)

    mail_object = mail_model.objects.filter(fuzzy_hash=ioc_id).first()
    if not mail_object:
        print(f"Mail {mail_type} with id {ioc_id} not found")
        return JsonResponse(
            {"success": False, "error": f"Mail {mail_type} does not exist"}, status=404
        )

    print(f"Mail {mail_type} {mail_object.id} found")
    update_ioc_level_and_cases(mail_object, mail_type, level)

    if mail_type == "body":
        obj_score, obj_confidence, obj_level = (
            mail_object.body_score,
            mail_object.body_confidence,
            mail_object.body_level,
        )
    else:  # header
        obj_score, obj_confidence, obj_level = (
            mail_object.header_score,
            mail_object.header_confidence,
            mail_object.header_level,
        )

    try:
        case = Case.objects.get(id=case_id)
    except Case.DoesNotExist:
        print(f"Case {case_id} not found")
        return JsonResponse({"success": False, "error": "Case does not exist"}, status=404)

    case_infos = {
        "id": case.id,
        "score": case.finalScore,
        "confidence": case.finalConfidence,
        "results": case.results,
    }

    print(
        f"Case {case.id} updated (score={case.finalScore}, confidence={case.finalConfidence})"
    )

    return JsonResponse(
        {
            "success": True,
            "score": obj_score,
            "confidence": obj_confidence,
            "level": obj_level,
            "case_infos": case_infos,
        }
    )
def handle_file(id, level, case_id):
    """Handle file based on the provided parameters.

    This function retrieves a file object based on the provided ID and updates its IOC level and cases.
    It also updates the linked hash object associated with the file.
    Finally, it updates a case object with the provided case ID.

    Args:
        id (int): The ID of the file.
        level (str): The IOC level to update.
        case_id (int): The ID of the case to update.

    Returns:
        dict: A JSON response containing the success status, updated scores, levels, and case information.

    Raises:
        None

    """
    file = File.objects.filter(linked_hash__value=id).first()
    if file:
        print(f"File with id {file.id} found")
        obj = update_ioc_level_and_cases(file, "file", level)
        obj_score = obj.file_score
        obj_confidence = obj.file_confidence
        obj_level = obj.file_level

        print(f"Updating linked hash with id {file.linked_hash.id}")

        hash_obj = update_ioc_level_and_cases(file.linked_hash, "hash", level)
        hash_obj_score = hash_obj.ioc_score
        hash_obj_confidence = hash_obj.ioc_confidence
        hash_obj_level = hash_obj.ioc_level

        case = Case.objects.get(id=case_id)
        case_infos = {
            "id": case.id,
            "score": case.finalScore,
            "confidence": case.finalConfidence,
            "results": case.results,
        }
        print(f"Case updated with id {case.id}, score {case.finalScore}, confidence {case.finalConfidence}, and results {case.results}")
        return JsonResponse({'success': True, 'score': obj_score, 'confidence': obj_confidence, 'level': obj_level, 'hash_score': hash_obj_score, 'hash_confidence': hash_obj_confidence, 'hash_level': hash_obj_level, 'case_infos': case_infos})
    else:
        print(f"File with linked hash {id} not found")
        return JsonResponse({'success': False, 'error': 'File does not exist'})

def handle_ioc(id, ioc_type, level, case_id):
    """Handle IOC (Indicator of Compromise) based on the given parameters.

    This function retrieves the IOC object based on the provided `id` and `ioc_type`.
    It then updates the IOC level and associated cases with the provided `level` and `case_id`.
    Finally, it returns a JSON response containing the success status, IOC score, IOC confidence,
    IOC level, and case information.

    Args:
        id (int): The ID of the IOC.
        ioc_type (str): The type of the IOC (e.g., 'ip', 'url', 'hash').
        level (int): The new level to update the IOC with.
        case_id (int): The ID of the associated case.

    Returns:
        dict: A JSON response containing the following keys:
            - 'success' (bool): Indicates whether the operation was successful.
            - 'score' (int): The updated IOC score.
            - 'confidence' (int): The updated IOC confidence.
            - 'level' (int): The updated IOC level.
            - 'case_infos' (dict): Information about the associated case, including the ID,
              final score, final confidence, and results.

    """
    if ioc_type == 'ip':
        obj = IP.objects.filter(address=id).first()
    elif ioc_type == 'url':
        obj = URL.objects.filter(id=id).first()
    elif ioc_type == 'hash':
        obj = Hash.objects.filter(value=id).first()
    if obj:
        print(f"{ioc_type} with id {obj.id} found")
        obj = update_ioc_level_and_cases(obj, ioc_type, level)
        obj_score = obj.ioc_score
        obj_confidence = obj.ioc_confidence
        obj_level = obj.ioc_level

        case = Case.objects.get(id=case_id)
        case_infos = {
            "id": case.id,
            "score": case.finalScore,
            "confidence": case.finalConfidence,
            "results": case.results,
        }
        print(f"Case updated with id {case.id}, score {case.finalScore}, confidence {case.finalConfidence}, and results {case.results}")
        return JsonResponse({'success': True, 'score': obj_score, 'confidence': obj_confidence, 'level': obj_level, 'case_infos': case_infos})
    else:
        print(f"{ioc_type} with id {id} not found")
        return JsonResponse({'success': False, 'error': f'{ioc_type.capitalize()} does not exist'})
    
def get_artifact_by_id(id):
    """Get artifact by ID.

    This function retrieves an artifact based on the provided ID. It first tries to find the artifact as an IP address,
    then as a URL, and finally as a hash value. If the artifact is not found in any of these categories, a warning
    message is logged and None is returned.

    Args:
        id (int): The ID of the artifact.

    Returns:
        IP or Hash or URL or None: The artifact object if found, otherwise None.
    """
    try:
        print(f"Trying to get artifact with id {id} as IP")
        return IP.objects.get(address=id)
    except IP.DoesNotExist:
        print(f"Artifact with id {id} not found as IP")

    try:
        print(f"Trying to get artifact with id {id} as URL")
        return Hash.objects.get(value=id)
    except Hash.DoesNotExist:
        print(f"Artifact with id {id} not found as Hash")

    try:
        print(f"Trying to get artifact with id {id} as Hash")
        return URL.objects.get(id=id)
    except URL.DoesNotExist:
        print(f"Artifact with id {id} not found as URL")

    print(f"Artifact with id {id} not found")
    return None