"""write_file — sandboxed file writes inside OUTPUT_DIR."""
import os


class FileMixin:
    def write_file(self, file_path: str, content: str) -> str:
        abs_work = os.path.abspath(self.working_directory)
        abs_file = os.path.abspath(
            os.path.join(self.working_directory, file_path)
        )

        if not abs_file.startswith(abs_work):
            return (f'Error: Cannot write to "{file_path}" as it is outside '
                    "the permitted working directory")

        if os.path.isdir(abs_file):
            return f'Error: Cannot write to "{file_path}" as it is a directory'

        try:
            dir_name = os.path.dirname(abs_file)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(abs_file, "w", encoding="utf-8") as f:
                f.write(content)
            return (f'Successfully wrote to "{file_path}" '
                    f"({len(content)} characters written)")
        except Exception as e:
            return f"Error: {e}"
