from download_modules.download_file_action import DownloadFile
from download_modules.module_models import DownloadModule

if __name__ == "__main__":
    module = DownloadModule()
    module.register(DownloadFile, "DownloadFile")
    module.run()
