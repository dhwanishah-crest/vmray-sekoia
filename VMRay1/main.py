from vmray_modules.build_report_action import BuildReport
from vmray_modules.download_file_action import DownloadFile
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.models import VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.submit_file_sample_action import SubmitFileSample

if __name__ == "__main__":
    module = VMRayModule()
    module.register(BuildReport, "BuildReport")
    module.register(DownloadFile, "DownloadFile")
    module.register(ExtractIocs, "ExtractIocs")
    module.register(SubmitFileSample, "SubmitFileSample")
    module.register(RenderReport, "RenderReport")
    module.run()
