import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CodeQLLanguageConfig:
    name: str
    codeql_language: str
    database_subdir: str
    query_pack: str
    cwe_query_path_template: str


@dataclass(frozen=True)
class CodeQLQueryResolution:
    query_dir: str
    experimental: bool
    fallback_to_experimental: bool


LANGUAGE_CONFIGS = {
    "java": CodeQLLanguageConfig(
        name="java",
        codeql_language="java",
        database_subdir="db-java",
        query_pack="java-queries",
        cwe_query_path_template="{exp}Security/CWE/CWE-{cwe_id}",
    ),
    "python": CodeQLLanguageConfig(
        name="python",
        codeql_language="python",
        database_subdir="db-python",
        query_pack="python-queries",
        cwe_query_path_template="{exp}Security/CWE-{cwe_id}",
    ),
    "cpp": CodeQLLanguageConfig(
        name="cpp",
        codeql_language="cpp",
        database_subdir="db-cpp",
        query_pack="cpp-queries",
        cwe_query_path_template="{exp}Security/CWE/CWE-{cwe_id}",
    ),
}


def normalize_language(language: str) -> str:
    normalized = language.strip().lower()
    aliases = {
        "py": "python",
        "c": "cpp",
        "c++": "cpp",
        "c/c++": "cpp",
    }
    return aliases.get(normalized, normalized)


def get_language_config(language: str) -> CodeQLLanguageConfig:
    normalized = normalize_language(language)
    if normalized not in LANGUAGE_CONFIGS:
        supported = ", ".join(sorted(LANGUAGE_CONFIGS))
        raise ValueError(f"Unsupported language `{language}`. Supported languages: {supported}")
    return LANGUAGE_CONFIGS[normalized]


def _version_key(version: str) -> tuple:
    parts = re.split(r"[.-]", version)
    key = []
    for part in parts:
        if part.isdigit():
            key.append(int(part))
        else:
            key.append(part)
    return tuple(key)


def discover_query_pack_version(codeql_dir: str, language: str) -> str:
    config = get_language_config(language)
    pack_dir = os.path.join(codeql_dir, "qlpacks", "codeql", config.query_pack)
    if not os.path.isdir(pack_dir):
        raise FileNotFoundError(f"Cannot find CodeQL query pack directory: {pack_dir}")

    versions = [
        entry
        for entry in os.listdir(pack_dir)
        if os.path.isdir(os.path.join(pack_dir, entry))
    ]
    if not versions:
        raise FileNotFoundError(f"No installed versions found in CodeQL query pack: {pack_dir}")
    return sorted(versions, key=_version_key)[-1]


def get_cwe_query_dir(codeql_dir: str, language: str, cwe_id: str, experimental: bool = False) -> str:
    config = get_language_config(language)
    version = discover_query_pack_version(codeql_dir, language)
    exp = "experimental/" if experimental else ""
    relative_query_path = config.cwe_query_path_template.format(exp=exp, cwe_id=cwe_id)
    return os.path.join(codeql_dir, "qlpacks", "codeql", config.query_pack, version, relative_query_path)


def resolve_cwe_query_dir(
        codeql_dir: str,
        language: str,
        cwe_id: str,
        experimental: bool = False,
        allow_experimental_fallback: bool = True,
) -> CodeQLQueryResolution:
    query_dir = get_cwe_query_dir(codeql_dir, language, cwe_id, experimental)
    if os.path.exists(query_dir):
        return CodeQLQueryResolution(
            query_dir=query_dir,
            experimental=experimental,
            fallback_to_experimental=False,
        )

    if experimental or not allow_experimental_fallback:
        return CodeQLQueryResolution(
            query_dir=query_dir,
            experimental=experimental,
            fallback_to_experimental=False,
        )

    experimental_query_dir = get_cwe_query_dir(codeql_dir, language, cwe_id, experimental=True)
    if os.path.exists(experimental_query_dir):
        return CodeQLQueryResolution(
            query_dir=experimental_query_dir,
            experimental=True,
            fallback_to_experimental=True,
        )

    return CodeQLQueryResolution(
        query_dir=query_dir,
        experimental=False,
        fallback_to_experimental=False,
    )
