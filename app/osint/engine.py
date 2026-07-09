from .detector import detect_target_type


def investigate(target):

    target_type = detect_target_type(target)

    return {

        "target": target,

        "type": target_type,

        "status": "Coming Soon"

    }