from vmray_modules.build_report_action import BuildReport
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.get_analysis_archive_action import GetAnalysisArchive
from vmray_modules.get_child_sample_report_action import GetChildSampleReport
from vmray_modules.get_child_samples_action import GetChildSamples
from vmray_modules.get_sample_iocs_action import GetSampleIocs
from vmray_modules.get_sample_mitre_attack_techniques_action import GetSampleMitreAttackTechniques
from vmray_modules.get_sample_relations_action import GetSampleRelations
from vmray_modules.get_sample_report_action import GetSampleReport
from vmray_modules.get_sample_screenshots_action import GetSampleScreenshots
from vmray_modules.get_sample_vtis_action import GetSampleVtis
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.get_submission_result_action import GetSubmissionResult
from vmray_modules.module_models import VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.submit_sample_action import SubmitSample
from vmray_modules.submit_url_action import SubmitUrl

if __name__ == "__main__":
    module = VMRayModule()
    module.register(BuildReport, "BuildReport")
    module.register(ExtractIocs, "ExtractIocs")
    module.register(SubmitUrl, "SubmitUrl")
    module.register(SubmitSample, "SubmitSample")
    module.register(GetSubmissionResult, "GetSubmissionResult")
    module.register(GetSamplesByHash, "GetSamplesByHash")
    module.register(GetChildSamples, "GetChildSamples")
    module.register(GetSampleRelations, "GetSampleRelations")
    module.register(GetChildSampleReport, "GetChildSampleReport")
    module.register(GetSampleIocs, "GetSampleIocs")
    module.register(GetSampleMitreAttackTechniques, "GetSampleMitreAttackTechniques")
    module.register(GetSampleVtis, "GetSampleVtis")
    module.register(GetSampleScreenshots, "GetSampleScreenshots")
    module.register(GetSampleReport, "GetSampleReport")
    module.register(GetAnalysisArchive, "GetAnalysisArchive")
    module.register(RenderReport, "RenderReport")
    module.run()
