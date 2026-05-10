from __future__ import annotations

import logging
import os
import sys
import warnings
from dataclasses import dataclass, field
from typing import Iterable, List, Set
from urllib.parse import urlsplit

from dotenv import load_dotenv
from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP

try:
    import urllib3
except ImportError:
    urllib3 = None

from src.config import get_app_config
from src.misp_mapper import MISPAttributeData


load_dotenv()


TAG_COLOURS = {
    "tlp:clear": "#ffffff",
    "source:article": "#3b82f6",
    "ioc:processed": "#64748b",
    "ioc-status:validated": "#22c55e",
    "ioc:source": "#0ea5e9",
    "ioc:context": "#94a3b8",
    "ioc-object:url": "#2563eb",
    "ioc-object:domain-ip": "#0891b2",
    "ioc-object:file": "#7c3aed",
    "confidence:high": "#16a34a",
    "confidence:medium": "#f59e0b",
    "confidence:low": "#dc2626",
}

@dataclass
class MISPAttributeChange:
    type: str
    value: str
    category: str
    to_ids: bool
    comment: str
    tags: List[str] = field(default_factory=list)


@dataclass
class MISPEventDiff:
    event_id: str
    new_attributes: List[MISPAttributeChange] = field(default_factory=list)
    unchanged_attributes: List[MISPAttributeChange] = field(default_factory=list)
    new_objects: List[MISPAttributeChange] = field(default_factory=list)
    unchanged_objects: List[MISPAttributeChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_attributes or self.new_objects)


@dataclass(frozen=True)
class MISPSourceData:
    type: str
    value: str
    category: str
    comment: str


warnings.filterwarnings("ignore")
logging.getLogger("pymisp").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)
if urllib3 is not None:
    urllib3.disable_warnings()


def to_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y"}


def build_misp_client() -> PyMISP:
    misp_url = os.getenv("MISP_URL")
    misp_key = os.getenv("MISP_KEY")
    verify_ssl = to_bool(os.getenv("MISP_VERIFY_SSL", "false"))
    timeout = float(os.getenv("MISP_TIMEOUT", "15"))

    if not misp_url or not misp_key:
        raise ValueError("Chýba MISP_URL alebo MISP_KEY v .env")

    return PyMISP(
        misp_url,
        misp_key,
        ssl=verify_ssl,
        timeout=timeout,
        http_headers={"Connection": "close"},
    )


def close_misp_client(misp: PyMISP) -> None:
    session = getattr(misp, "_PyMISP__session", None)
    if session is None:
        return

    try:
        session.close()
    except Exception:
        pass


def _add_tags(target: MISPEvent | MISPAttribute, tags: Iterable[str]) -> None:
    for tag in tags:
        try:
            target.add_tag(tag)
        except Exception:
            continue


def _add_misp_object_tag(obj: MISPObject, tag: str) -> None:
    try:
        obj._add_tag(tag)
    except Exception:
        pass


def _load_existing_tags(misp: PyMISP, tag_names: Iterable[str]) -> Set[str]:
    existing_tags: Set[str] = set()
    for tag_name in sorted(set(tag_names)):
        try:
            if misp.search_tags(tag_name, strict_tagname=True):
                existing_tags.add(tag_name)
        except Exception:
            continue
    return existing_tags


def _response_has_error(response) -> bool:
    if isinstance(response, dict):
        return "errors" in response or response.get("saved") is False
    if isinstance(response, list):
        return any(_response_has_error(item) for item in response)
    return False


def _attach_tags(
    misp: PyMISP,
    target,
    tags: Iterable[str],
    existing_tags: Set[str],
) -> None:
    for tag in tags:
        if tag not in existing_tags:
            continue

        try:
            response = misp.tag(target, tag)
            if _response_has_error(response):
                continue
        except Exception:
            continue


def _event_tags(attributes: List[MISPAttributeData]) -> List[str]:
    tags = {
        "tlp:clear",
        "source:article",
        "ioc:processed",
        "ioc-status:validated",
    }

    confidence_levels = set()
    ioc_types = set()

    for attr in attributes:
        ioc_types.add(attr.type)
        for tag in attr.tags:
            if tag.startswith("confidence:"):
                confidence_levels.add(tag)

    tags.update(confidence_levels)
    tags.update(f"ioc-contains-type:{ioc_type}" for ioc_type in sorted(ioc_types))
    return sorted(tags)


def _object_tags(obj_name: str) -> List[str]:
    return ["source:article", "ioc-status:validated", f"ioc-object:{obj_name}"]


def _all_runtime_tags(attributes: List[MISPAttributeData]) -> Set[str]:
    tags = set(_event_tags(attributes))
    tags.update(["source:article", "ioc:source", "ioc:context"])

    for attr in attributes:
        tags.update(attr.tags)

    for obj_name in {"url", "domain-ip", "file"}:
        tags.update(_object_tags(obj_name))

    return tags


def _build_misp_objects(attributes: List[MISPAttributeData]) -> List[MISPObject]:
    objects: List[MISPObject] = []

    for attr in attributes:
        if attr.type == "url":
            obj = MISPObject("url", strict=False)
            object_attr = obj.add_attribute(
                "url",
                simple_value=attr.value,
                to_ids=attr.to_ids,
                comment=attr.comment,
            )
            for tag in _object_tags("url") + attr.tags:
                _add_misp_object_tag(obj, tag)
            created_attributes = object_attr if isinstance(object_attr, list) else [object_attr]
            for created_attr in created_attributes:
                _add_tags(created_attr, attr.tags)
            objects.append(obj)

        elif attr.type in {"domain", "ip-dst", "ip-src"}:
            obj = MISPObject("domain-ip", strict=False)
            relation = "domain" if attr.type == "domain" else "ip"
            object_attr = obj.add_attribute(
                relation,
                simple_value=attr.value,
                to_ids=attr.to_ids,
                comment=attr.comment,
            )
            for tag in _object_tags("domain-ip") + attr.tags:
                _add_misp_object_tag(obj, tag)
            created_attributes = object_attr if isinstance(object_attr, list) else [object_attr]
            for created_attr in created_attributes:
                _add_tags(created_attr, attr.tags)
            objects.append(obj)

        elif attr.type in {"md5", "sha1", "sha256"}:
            obj = MISPObject("file", strict=False)
            object_attr = obj.add_attribute(
                attr.type,
                simple_value=attr.value,
                to_ids=attr.to_ids,
                comment=attr.comment,
            )
            for tag in _object_tags("file") + attr.tags:
                _add_misp_object_tag(obj, tag)
            created_attributes = object_attr if isinstance(object_attr, list) else [object_attr]
            for created_attr in created_attributes:
                _add_tags(created_attr, attr.tags)
            objects.append(obj)

    return objects


def _add_attribute(event: MISPEvent, attr: MISPAttributeData) -> None:
    created = event.add_attribute(
        type=attr.type,
        value=attr.value,
        category=attr.category,
        to_ids=attr.to_ids,
        comment=attr.comment,
    )

    created_attributes = created if isinstance(created, list) else [created]
    for created_attr in created_attributes:
        _add_tags(created_attr, attr.tags)


def _mark_event_publishable(event: MISPEvent) -> None:
    misp_config = get_app_config().misp
    event.distribution = misp_config.distribution
    event.analysis = misp_config.analysis
    event.published = False
    try:
        event.unpublish()
    except Exception:
        pass


def _publish_event_if_enabled(misp: PyMISP, event_id: str) -> None:
    misp_config = get_app_config().misp
    if not misp_config.publish_event:
        return

    try:
        misp.publish(event_id)
    except Exception:
        pass


def _to_misp_attribute(attr: MISPAttributeData) -> MISPAttribute:
    misp_attr = MISPAttribute()
    misp_attr.from_dict(
        type=attr.type,
        value=attr.value,
        category=attr.category,
        to_ids=attr.to_ids,
        comment=attr.comment,
    )
    _add_tags(misp_attr, attr.tags)
    return misp_attr


def _is_web_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() in {"http", "https"} and bool(parts.netloc)


def _source_data(source_url: str) -> MISPSourceData:
    if _is_web_url(source_url):
        return MISPSourceData(
            type="link",
            value=source_url,
            category="External analysis",
            comment="Source article URL",
        )

    return MISPSourceData(
        type="text",
        value=source_url,
        category="External analysis",
        comment="Source file path",
    )


def _source_attribute(source_url: str) -> MISPAttributeData:
    source = _source_data(source_url)
    return MISPAttributeData(
        type=source.type,
        value=source.value,
        category=source.category,
        to_ids=False,
        comment=source.comment,
        tags=["source:article", "ioc:source"],
    )


def _title_attribute(title: str) -> MISPAttributeData:
    return MISPAttributeData(
        type="text",
        value=title,
        category="External analysis",
        to_ids=False,
        comment="Source article title",
        tags=["source:article", "ioc:context"],
    )


def _is_object_backed_attribute(attr: MISPAttributeData) -> bool:
    return attr.type in {"url", "domain", "ip-dst", "ip-src", "md5", "sha1", "sha256"}


def _standalone_ioc_attributes(attributes: List[MISPAttributeData]) -> List[MISPAttributeData]:
    return [attr for attr in attributes if not _is_object_backed_attribute(attr)]


def _object_backed_ioc_attributes(attributes: List[MISPAttributeData]) -> List[MISPAttributeData]:
    return [attr for attr in attributes if _is_object_backed_attribute(attr)]


def _proposed_attributes(
    title: str,
    source_url: str,
    attributes: List[MISPAttributeData],
) -> List[MISPAttributeData]:
    return [_source_attribute(source_url), _title_attribute(title), *_standalone_ioc_attributes(attributes)]


def _attribute_key(attr_type: str, value: str) -> tuple[str, str]:
    return attr_type, value.strip()


def _attribute_data_key(attr: MISPAttributeData) -> tuple[str, str]:
    return _attribute_key(attr.type, attr.value)


def _to_attribute_change(attr: MISPAttributeData) -> MISPAttributeChange:
    return MISPAttributeChange(
        type=attr.type,
        value=attr.value,
        category=attr.category,
        to_ids=attr.to_ids,
        comment=attr.comment,
        tags=list(attr.tags),
    )


def _iter_event_attributes(event) -> Iterable:
    if isinstance(event, MISPEvent):
        return getattr(event, "Attribute", []) or []

    if isinstance(event, dict):
        response = event.get("response", event)
        if isinstance(response, list) and response:
            response = response[0]
        if isinstance(response, dict):
            event_data = response.get("Event", response)
            if isinstance(event_data, dict):
                return event_data.get("Attribute", []) or []

    return []


def _iter_event_objects(event) -> Iterable:
    if isinstance(event, MISPEvent):
        return getattr(event, "Object", []) or []

    if isinstance(event, dict):
        response = event.get("response", event)
        if isinstance(response, list) and response:
            response = response[0]
        if isinstance(response, dict):
            event_data = response.get("Event", response)
            if isinstance(event_data, dict):
                return event_data.get("Object", []) or []

    return []


def _existing_attribute_keys(event) -> Set[tuple[str, str]]:
    keys: Set[tuple[str, str]] = set()
    for attr in _iter_event_attributes(event):
        if isinstance(attr, MISPAttribute):
            attr_type = getattr(attr, "type", None)
            value = getattr(attr, "value", None)
        elif isinstance(attr, dict):
            data = attr.get("Attribute", attr)
            if not isinstance(data, dict):
                continue
            attr_type = data.get("type")
            value = data.get("value")
        else:
            continue

        if attr_type and value:
            keys.add(_attribute_key(str(attr_type), str(value)))

    return keys


def _object_relation_for_attribute_type(attr_type: str) -> tuple[str, str] | None:
    if attr_type == "url":
        return "url", "url"
    if attr_type == "domain":
        return "domain-ip", "domain"
    if attr_type in {"ip-dst", "ip-src"}:
        return "domain-ip", "ip"
    if attr_type in {"md5", "sha1", "sha256"}:
        return "file", attr_type
    return None


def _object_attribute_key(attr: MISPAttributeData) -> tuple[str, str, str] | None:
    relation = _object_relation_for_attribute_type(attr.type)
    if relation is None:
        return None
    object_name, object_relation = relation
    return object_name, object_relation, attr.value.strip()


def _existing_object_attribute_keys(event) -> Set[tuple[str, str, str]]:
    keys: Set[tuple[str, str, str]] = set()

    for obj in _iter_event_objects(event):
        if isinstance(obj, MISPObject):
            object_name = getattr(obj, "name", None)
            object_attributes = getattr(obj, "Attribute", []) or []
        elif isinstance(obj, dict):
            object_data = obj.get("Object", obj)
            if not isinstance(object_data, dict):
                continue
            object_name = object_data.get("name")
            object_attributes = object_data.get("Attribute", []) or []
        else:
            continue

        if not object_name:
            continue

        for object_attr in object_attributes:
            if isinstance(object_attr, dict):
                attr_data = object_attr.get("Attribute", object_attr)
                if not isinstance(attr_data, dict):
                    continue
                relation = attr_data.get("object_relation")
                value = attr_data.get("value")
            else:
                relation = getattr(object_attr, "object_relation", None)
                value = getattr(object_attr, "value", None)

            if relation and value:
                keys.add((str(object_name), str(relation), str(value).strip()))

    return keys


def _build_event_diff(
    event_id: str,
    existing_event,
    title: str,
    source_url: str,
    attributes: List[MISPAttributeData],
) -> MISPEventDiff:
    existing_keys = _existing_attribute_keys(existing_event)
    existing_object_keys = _existing_object_attribute_keys(existing_event)
    diff = MISPEventDiff(event_id=event_id)

    for attr in _proposed_attributes(title, source_url, attributes):
        change = _to_attribute_change(attr)
        if _attribute_data_key(attr) in existing_keys:
            diff.unchanged_attributes.append(change)
        else:
            diff.new_attributes.append(change)

    for attr in _object_backed_ioc_attributes(attributes):
        change = _to_attribute_change(attr)
        object_key = _object_attribute_key(attr)
        if _attribute_data_key(attr) in existing_keys or (object_key and object_key in existing_object_keys):
            diff.unchanged_objects.append(change)
        else:
            diff.new_objects.append(change)

    return diff


def get_existing_event_diff(
    event_id: str,
    title: str,
    source_url: str,
    attributes: List[MISPAttributeData],
) -> MISPEventDiff:
    misp = build_misp_client()
    try:
        existing_event = misp.get_event(event_id, pythonify=True)
        return _build_event_diff(event_id, existing_event, title, source_url, attributes)
    finally:
        close_misp_client(misp)


def _extract_existing_event_id(search_results) -> str | None:
    if isinstance(search_results, dict):
        response = search_results.get("response", search_results)
        if isinstance(response, dict) and isinstance(response.get("Attribute"), list):
            search_results = response["Attribute"]
        elif isinstance(response, dict) and isinstance(response.get("Event"), list):
            search_results = response["Event"]
        elif isinstance(response, list):
            search_results = response
        else:
            search_results = [response]

    if not isinstance(search_results, list):
        return None

    for item in search_results:
        if isinstance(item, MISPAttribute):
            event_id = getattr(item, "event_id", None)
            return str(event_id) if event_id else None

        if not isinstance(item, dict):
            continue

        attribute = item.get("Attribute", item)
        if isinstance(attribute, dict):
            event_id = attribute.get("event_id")
            if event_id:
                return str(event_id)
            if attribute.get("Event") and isinstance(attribute["Event"], dict):
                nested_event_id = attribute["Event"].get("id")
                if nested_event_id:
                    return str(nested_event_id)
        elif isinstance(attribute, list):
            for nested_attribute in attribute:
                if isinstance(nested_attribute, dict) and nested_attribute.get("event_id"):
                    return str(nested_attribute["event_id"])

        event = item.get("Event")
        if isinstance(event, dict) and event.get("id"):
            return str(event["id"])
        if isinstance(event, list):
            for nested_event in event:
                if isinstance(nested_event, dict) and nested_event.get("id"):
                    return str(nested_event["id"])

        if item.get("id") and "event_id" not in item:
            return str(item["id"])

    return None


def _find_existing_event_by_source_url(misp: PyMISP, source_url: str) -> str | None:
    source = _source_data(source_url)
    try:
        results = misp.search(
            controller="attributes",
            return_format="json",
            value=source_url,
            type_attribute=source.type,
            limit=1,
            include_context=True,
            include_event_uuid=True,
            pythonify=False,
        )
        existing_event_id = _extract_existing_event_id(results)
        if existing_event_id:
            return existing_event_id

        results = misp.search(
            controller="events",
            return_format="json",
            value=source_url,
            type_attribute=source.type,
            limit=1,
            metadata=False,
            include_event_uuid=True,
            pythonify=False,
        )
        return _extract_existing_event_id(results)
    except Exception as exc:
        print(f"Warning: Nepodarilo sa overiť existujúci MISP event: {exc}", file=sys.stderr)
        raise RuntimeError(
            "Kontrola duplicity v MISP zlyhala, nový event nebol vytvorený."
        ) from exc


def find_existing_event_by_source_url(source_url: str) -> str | None:
    misp = build_misp_client()
    try:
        return _find_existing_event_by_source_url(misp, source_url)
    finally:
        close_misp_client(misp)


def update_existing_event(
    event_id: str,
    title: str,
    source_url: str,
    attributes: List[MISPAttributeData],
) -> MISPEventDiff:
    misp = build_misp_client()
    try:
        existing_event = misp.get_event(event_id, pythonify=True)
        if isinstance(existing_event, MISPEvent):
            _mark_event_publishable(existing_event)
            try:
                misp.update_event(existing_event, event_id=event_id, pythonify=True)
            except Exception:
                pass

        diff = _build_event_diff(event_id, existing_event, title, source_url, attributes)
        if not diff.has_changes:
            return diff

        proposed_by_key = {
            _attribute_data_key(attr): attr
            for attr in _proposed_attributes(title, source_url, attributes)
        }
        existing_tags = _load_existing_tags(misp, _all_runtime_tags(attributes))

        for change in diff.new_attributes:
            attr = proposed_by_key[(change.type, change.value)]
            created_attr = misp.add_attribute(
                event_id,
                _to_misp_attribute(attr),
                pythonify=True,
                break_on_duplicate=False,
            )
            created_attributes = created_attr if isinstance(created_attr, list) else [created_attr]
            for item in created_attributes:
                _attach_tags(misp, item, attr.tags, existing_tags)

        object_attributes_by_key = {
            _attribute_data_key(attr): attr
            for attr in _object_backed_ioc_attributes(attributes)
        }
        new_ioc_attributes = [
            object_attributes_by_key[(change.type, change.value)]
            for change in diff.new_objects
            if (change.type, change.value) in object_attributes_by_key
        ]

        for obj in _build_misp_objects(new_ioc_attributes):
            try:
                misp.add_object(event_id, obj, pythonify=True)
            except Exception:
                continue

        refreshed_event = misp.get_event(event_id, pythonify=True)
        _publish_event_if_enabled(misp, event_id)
        return _build_event_diff(event_id, refreshed_event, title, source_url, attributes)
    finally:
        close_misp_client(misp)


def create_event(
    title: str,
    source_url: str,
    attributes: List[MISPAttributeData],
) -> tuple[str, bool]:
    misp = build_misp_client()
    try:
        existing_event_id = _find_existing_event_by_source_url(misp, source_url)
        if existing_event_id:
            return existing_event_id, False

        event = MISPEvent()
        event.info = f"Auto-import IoC from article: {title}"
        event.threat_level_id = 2
        _mark_event_publishable(event)

        _add_tags(event, _event_tags(attributes))

        source = _source_data(source_url)
        source_attribute = event.add_attribute(
            type=source.type,
            value=source.value,
            category=source.category,
            to_ids=False,
            comment=source.comment,
        )
        _add_tags(source_attribute, ["source:article", "ioc:source"])

        title_attribute = event.add_attribute(
            type="text",
            value=title,
            category="External analysis",
            to_ids=False,
            comment="Source article title",
        )
        _add_tags(title_attribute, ["source:article", "ioc:context"])

        for attr in _standalone_ioc_attributes(attributes):
            try:
                _add_attribute(event, attr)
            except Exception:
                continue

        for obj in _build_misp_objects(_object_backed_ioc_attributes(attributes)):
            try:
                event.add_object(obj)
            except Exception:
                continue

        created_event = misp.add_event(event, pythonify=True)
        existing_tags = _load_existing_tags(misp, _all_runtime_tags(attributes))
        _attach_tags(misp, created_event, _event_tags(attributes), existing_tags)
        _attach_created_attribute_tags(
            misp=misp,
            created_event=created_event,
            source_url=source_url,
            title=title,
            attributes=attributes,
            existing_tags=existing_tags,
        )
        _publish_event_if_enabled(misp, str(created_event.id))
        return str(created_event.id), True
    finally:
        close_misp_client(misp)


def _attach_created_attribute_tags(
    misp: PyMISP,
    created_event: MISPEvent,
    source_url: str,
    title: str,
    attributes: List[MISPAttributeData],
    existing_tags: Set[str],
) -> None:
    source = _source_data(source_url)
    tags_by_key = {
        (source.type, source.value): ["source:article", "ioc:source"],
        ("text", title): ["source:article", "ioc:context"],
    }
    for attr in attributes:
        tags_by_key[(attr.type, attr.value)] = attr.tags

    created_attributes = getattr(created_event, "Attribute", [])
    for created_attr in created_attributes:
        key = (getattr(created_attr, "type", ""), getattr(created_attr, "value", ""))
        tags = tags_by_key.get(key)
        if tags:
            _attach_tags(misp, created_attr, tags, existing_tags)
