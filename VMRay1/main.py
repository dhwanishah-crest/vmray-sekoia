from vmray_modules.build_report_action import BuildReport
from vmray_modules.check_submission_status_action import CheckSubmissionStatus
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.get_child_sample_report_action import GetChildSampleReport
from vmray_modules.get_child_samples_action import GetChildSamples
from vmray_modules.get_sample_relations_action import GetSampleRelations
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.models import VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.start_file_submission_action import StartFileSubmission
from vmray_modules.start_url_submission_action import StartUrlSubmission
from vmray_modules.submit_file_sample_action import SubmitFileSample
from vmray_modules.submit_url_sample_action import SubmitUrlSample

if __name__ == "__main__":
    module = VMRayModule()
    module.register(BuildReport, "BuildReport")
    module.register(ExtractIocs, "ExtractIocs")
    module.register(SubmitUrlSample, "SubmitUrlSample")
    module.register(SubmitFileSample, "SubmitFileSample")
    module.register(StartUrlSubmission, "StartUrlSubmission")
    module.register(StartFileSubmission, "StartFileSubmission")
    module.register(CheckSubmissionStatus, "CheckSubmissionStatus")
    module.register(GetSamplesByHash, "GetSamplesByHash")
    module.register(GetChildSamples, "GetChildSamples")
    module.register(GetSampleRelations, "GetSampleRelations")
    module.register(GetChildSampleReport, "GetChildSampleReport")
    module.register(RenderReport, "RenderReport")
    module.run()
