import json
import pathlib
import typing


class ConfigServiceMailConfigSocials(typing.TypedDict):
    facebook: str
    twitter: str
    instagram: str
    linkedin: str
    youtube: str


ConfigServiceMailConfigLogos = typing.TypedDict(
    "ConfigServiceMailConfigLogos",
    {
        "compagny": str,
        "acknowledge-badmail": str,
    },
)

ConfigServiceMailConfig = typing.TypedDict(
    "ConfigServiceMailConfig",
    {
        "server": str,
        "port": int,
        "username": str,
        "footer": str,
        "group": str,
        "suspicious_web": str,
        "global": str,
        "global_url": str,
        "socials": ConfigServiceMailConfigSocials,
        "glossary": str,
        "inquiry": str,
        "inquiry_text": str,
        "submissions": str,
        "security": str,
        "security_msg": str,
        "logos": ConfigServiceMailConfigLogos,
    },
)


class ConfigServiceGlobalConfig(typing.TypedDict):
    mail: ConfigServiceMailConfig


class ConfigService:
    def __init__(self, config_file_path: pathlib.Path) -> None:
        self.__config_file_path = config_file_path

    def read_config_file(self) -> ConfigServiceGlobalConfig:
        if not self.__config_file_path.exists():
            raise FileNotFoundError(
                f"{self.__config_file_path.absolute()} does not exist."
            )

        with open(self.__config_file_path, "r") as stream:
            config = json.load(stream)

        return ConfigServiceGlobalConfig(config)
