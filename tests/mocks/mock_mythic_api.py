"""Mock implementation of the mythic module API calls."""

import json


class MockMythicAPI:
    """Mock implementation of the mythic module API calls."""

    def __init__(self, test_data_file: str):
        with open(test_data_file, 'r', encoding='utf-8') as f:
            self.test_data = json.load(f)

    async def login(self, **kwargs):
        """Mock mythic.login() - just return a fake instance."""
        # Validate kwargs if needed
        if not kwargs.get("apitoken") or not kwargs.get("server_ip"):
            raise ValueError("Missing required login parameters")

        return "mock_mythic_instance"

    async def get_all_callbacks(self, instance):
        """Mock mythic.get_all_callbacks() - return test callback data."""
        self._validate_mythic_instance(instance)
        return self.test_data["callbacks"]

    async def get_all_tasks(self, instance, callback_display_id):
        """Mock mythic.get_all_tasks() - filter tasks by callback_display_id."""
        tasks = []

        self._validate_mythic_instance(instance)

        # Filter tasks by callback display_id
        for task in self.test_data.get("tasks", []):
            if task.get("callback", {}).get("display_id") == callback_display_id:
                tasks.append(task)

        return tasks

    async def get_all_task_output_by_id(self, instance, task_id):
        """Mock mythic.get_all_task_output_by_id() - find output by task ID."""
        outputs = []

        self._validate_mythic_instance(instance)

        # Search outputs by task ID
        for output in self.test_data.get("outputs", []):
            if output.get("task", {}).get("display_id") == task_id:
                # Return in the format the real API returns
                outputs.append(output)

        return outputs

    async def get_all_task_output(self, instance, batch_size=10):
        """Mock mythic.get_all_task_output() - yield all outputs."""
        cursor = 0
        self._validate_mythic_instance(instance)

        try:
            while True:
                batch = self.test_data.get("outputs", [])[cursor:cursor + batch_size]
                if not batch:
                    break
                yield batch
                cursor += batch_size
        except Exception:
            pass

    def _validate_mythic_instance(self, instance=None):
        if not instance:
            raise ValueError("Mythic instance is required but was not provided.")
