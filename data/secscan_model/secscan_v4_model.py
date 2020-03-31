import logging
import itertools

from collections import namedtuple
from math import log10
from peewee import fn, JOIN
from enum import Enum

from data.secscan_model.interface import SecurityScannerInterface
from data.secscan_model.datatypes import (
    ScanLookupStatus,
    SecurityInformationLookupResult,
    SecurityInformation,
    Feature,
    Layer,
    Vulnerability,
)
from data.registry_model.datatypes import Manifest as ManifestDataType
from data.registry_model import registry_model
from util.migrate.allocator import yield_random_entries
from util.secscan.validator import V4SecurityConfigValidator
from util.secscan.v4.api import ClairSecurityScannerAPI, APIRequestFailure
from util.secscan import PRIORITY_LEVELS
from util.config import URLSchemeAndHostname

from data.database import (
    Manifest,
    ManifestSecurityStatus,
    IndexerVersion,
    IndexStatus,
    Repository,
    User,
    db_transaction,
)


logger = logging.getLogger(__name__)


IndexReportState = namedtuple("IndexReportState", ["Index_Finished", "Index_Error"])(
    "IndexFinished", "IndexError"
)


class ScanToken(namedtuple("NextScanToken", ["min_id"])):
    """
    ScanToken represents an opaque token that can be passed between runs of the security worker
    to continue scanning whereever the previous run left off. Note that the data of the token is
    *opaque* to the security worker, and the security worker should *not* pull any data out or modify
    the token in any way.
    """


class V4SecurityScanner(SecurityScannerInterface):
    """
    Implementation of the security scanner interface for Clair V4 API-compatible implementations.
    """

    def __init__(self, app, instance_keys, storage):
        self.app = app
        self.storage = storage

        validator = V4SecurityConfigValidator(
            app.config.get("FEATURE_SECURITY_SCANNER", False),
            app.config.get("SECURITY_SCANNER_V4_ENDPOINT"),
        )

        if not validator.valid():
            logger.warning("Failed to validate security scanner V4 configuration")
            return

        self._secscan_api = ClairSecurityScannerAPI(
            endpoint=app.config.get("SECURITY_SCANNER_V4_ENDPOINT"),
            client=app.config.get("HTTPCLIENT"),
            storage=storage,
        )

    def load_security_information(self, manifest_or_legacy_image, include_vulnerabilities=False):
        if not isinstance(manifest_or_legacy_image, ManifestDataType):
            return None

        status = None
        try:
            status = ManifestSecurityStatus.get(manifest=manifest_or_legacy_image._db_id)
        except ManifestSecurityStatus.DoesNotExist:
            return SecurityInformationLookupResult.with_status(ScanLookupStatus.NOT_YET_INDEXED)

        if status.index_status == IndexStatus.FAILED:
            return SecurityInformationLookupResult.with_status(ScanLookupStatus.FAILED_TO_INDEX)

        if status.index_status == IndexStatus.MANIFEST_UNSUPPORTED:
            return SecurityInformationLookupResult.with_status(
                ScanLookupStatus.UNSUPPORTED_FOR_INDEXING
            )

        if status.index_status == IndexStatus.IN_PROGRESS:
            return SecurityInformationLookupResult.with_status(ScanLookupStatus.NOT_YET_INDEXED)

        assert status.index_status == IndexStatus.COMPLETED

        try:
            report = self._secscan_api.vulnerability_report(manifest_or_legacy_image.digest)
        except APIRequestFailure as arf:
            return SecurityInformationLookupResult.for_request_error(str(arf))

        if report is None:
            return SecurityInformationLookupResult.with_status(ScanLookupStatus.NOT_YET_INDEXED)

        # TODO(alecmerdler): Provide a way to indicate the current scan is outdated (`report.state != status.indexer_hash`)

        return SecurityInformationLookupResult.for_data(
            SecurityInformation(Layer(features_for(report)))
        )

    def perform_indexing(self, start_token=None):
        whitelisted_namespaces = self.app.config.get("SECURITY_SCANNER_V4_NAMESPACE_WHITELIST", [])
        try:
            indexer_state = self._secscan_api.state()
        except APIRequestFailure:
            print(
                "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
            )
            return None

        def eligible_manifests(base_query):
            return (
                base_query.join(Repository)
                .join(User)
                .where(User.username << whitelisted_namespaces)
            )

        min_id = (
            start_token
            if start_token is not None
            else Manifest.select(fn.Min(Manifest.id)).scalar()
        )
        max_id = Manifest.select(fn.Max(Manifest.id)).scalar()

        if max_id is None or min_id is None or min_id > max_id:
            return None

        # TODO(alecmerdler): Filter out any `Manifests` that are still being uploaded
        def not_indexed_query():
            return (
                eligible_manifests(Manifest.select())
                .switch(Manifest)
                .join(ManifestSecurityStatus, JOIN.LEFT_OUTER)
                .where(ManifestSecurityStatus.id >> None)
            )

        def index_error_query():
            return (
                eligible_manifests(Manifest.select())
                .switch(Manifest)
                .join(ManifestSecurityStatus)
                .where(ManifestSecurityStatus.index_status == IndexStatus.FAILED)
            )

        def needs_reindexing_query(indexer_hash):
            return (
                eligible_manifests(Manifest.select())
                .switch(Manifest)
                .join(ManifestSecurityStatus)
                .where(ManifestSecurityStatus.indexer_hash != indexer_hash)
            )

        # 4^log10(total) gives us a scalable batch size into the billions.
        batch_size = int(4 ** log10(max(10, max_id - min_id)))

        iterator = itertools.chain(
            yield_random_entries(not_indexed_query, Manifest.id, batch_size, max_id, min_id,),
            yield_random_entries(index_error_query, Manifest.id, batch_size, max_id, min_id,),
            yield_random_entries(
                lambda: needs_reindexing_query(indexer_state),
                Manifest.id,
                batch_size,
                max_id,
                min_id,
            ),
        )

        for candidate, abt, num_remaining in iterator:
            manifest = ManifestDataType.for_manifest(candidate, None)
            layers = registry_model.list_manifest_layers(manifest, self.storage, True)

            logger.debug(
                "Indexing %s/%s@%s"
                % (candidate.repository.namespace_user, candidate.repository.name, manifest.digest)
            )

            try:
                (report, state) = self._secscan_api.index(manifest, layers)
            except APIRequestFailure:
                logger.exception("Failed to perform indexing, security scanner API error")
                return None

            with db_transaction():
                ManifestSecurityStatus.delete().where(
                    ManifestSecurityStatus.manifest == candidate
                ).execute()
                ManifestSecurityStatus.create(
                    manifest=candidate,
                    repository=candidate.repository,
                    error_json=report["err"],
                    index_status=(
                        IndexStatus.FAILED
                        if report["state"] == IndexReportState.Index_Error
                        else IndexStatus.COMPLETED
                    ),
                    indexer_hash=state,
                    indexer_version=IndexerVersion.V4,
                    metadata_json={},
                )

        return ScanToken(max_id + 1)

    def register_model_cleanup_callbacks(self, data_model_config):
        pass

    @property
    def legacy_api_handler(self):
        raise NotImplementedError("Unsupported for this security scanner version")


def features_for(report):
    """
    Transforms a Clair v4 `VulnerabilityReport` dict into the standard shape of a 
    Quay Security scanner response.
    """

    features = []
    for pkg_id, pkg in report["packages"].items():
        pkg_env = report["environments"][pkg_id][0]
        pkg_vulns = [
            report["vulnerabilities"][vuln_id]
            for vuln_id in report["package_vulnerabilities"].get(pkg_id, [])
        ]

        features.append(
            Feature(
                pkg["name"],
                "",
                "",
                pkg_env["introduced_in"],
                pkg["version"],
                [
                    Vulnerability(
                        vuln["normalized_severity"]
                        if vuln["normalized_severity"]
                        else PRIORITY_LEVELS["Unknown"]["value"],
                        "",
                        vuln["links"],
                        vuln["fixed_in_version"] if vuln["fixed_in_version"] != "0" else "",
                        vuln["description"],
                        vuln["name"],
                        None,
                    )
                    for vuln in pkg_vulns
                ],
            )
        )

    return features
