"""Utility to capture real Mythic data for testing purposes."""
import sys
import json
import asyncio
import logging
from typing import AsyncIterator, Iterator, TypeVar
from syncer import sync
from mythic import mythic

T = TypeVar('T')

async def get_all_task_outputs_async(mythic_instance):
    """Async generator that gets all outputs by fetching fixed-size batches until exhausted."""

    batch_size = 7  # Fixed reasonable batch size
    offset = 0  # Track how many we've processed

    while True:
        print(f"Fetching batch starting at offset {offset}")

        # Get current batch - but how do we specify offset?
        # This is where we hit the API limitation again...
        output_generator = mythic.get_all_task_output(mythic_instance, batch_size=batch_size)

        batch_items = []
        outputs = []
        async for item in output_generator:
            for output in item:
                print(
                    f"Fetched item with task display_id: {output.get('task', {}).get('display_id')}"
                )
                outputs.append(output)
            batch_items.append(item)

        print(f"Got {len(outputs)} outputs from {len(batch_items)} batches")

        # If we got no items, we're done
        if not batch_items:
            break

        # Yield items from this batch
        for item in batch_items:
            yield item

        offset += len(batch_items)

        # If we got fewer items than batch_size, we've reached the end
        if len(batch_items) < batch_size:
            break

def async_iterable_to_sync_iterable(iterator: AsyncIterator[T]) -> Iterator[T]:
    """Convert an async iterator to a sync iterator."""
    loop = asyncio.get_event_loop()

    try:
        while True:
            try:
                result = loop.run_until_complete(anext(iterator))
                print("🟡 async_iterable_to_sync_iterable:")
                yield result
            except StopAsyncIteration:
                print("🟡 async_iterable_to_sync_iterable: StopAsyncIteration")
                break
    finally:
        loop.close()

def get_all_task_outputs_sync(mythic_instance):
    """
    Sync generator that properly streams outputs from Mythic
    """
    batch_size = 1

    # Get all outputs in one go, then yield them
    async_output_iterator = mythic.get_all_task_output(mythic_instance, batch_size=batch_size)
    for output in async_iterable_to_sync_iterable(async_output_iterator):
        yield output

def get_data_streams(mythic_instance):
    """Sync generator that streams all outputs using exponentially increasing batch sizes."""

    async def _get_batch_generator(batch_size):
        """Get one batch of the specified size."""
        batch_generator = mythic.get_all_task_output(mythic_instance, batch_size=batch_size)
        return [item async for item in batch_generator]

    batch_size = 5
    yielded_count = 0

    while True:
        print(f"Fetching batch of size {batch_size}")

        # Get current batch
        batch_items = asyncio.run(_get_batch_generator(batch_size))

        print(f"Got {len(batch_items)} batches")

        # Yield items from this batch (but only new ones beyond what we've already yielded)
        new_items = batch_items[yielded_count:]

        for item in new_items:
            yield item

        yielded_count += len(new_items)

        # If we got fewer items than batch_size, we have everything
        if len(batch_items) < batch_size:
            print(f"Got all data. Total items: {yielded_count}")
            break

async def capture_mythic_data(server, token, output_file):
    """Capture real Mythic data for testing purposes."""

    # Connect and get real data
    mythic_instance = await mythic.login(
        apitoken=token,
        server_ip=server,
        server_port=7443,
        timeout=-1,
        logging_level=logging.CRITICAL,
    )

    captured_data = {
        "callbacks": [],
        "tasks": [],
        "outputs": []
    }

    # Capture callback metadata
    raw_callbacks = await mythic.get_all_callbacks(
        mythic_instance,
        custom_return_attributes="id,display_id,domain,user,host,agent_callback_id"
    )

    captured_data["callbacks"].extend(raw_callbacks)

    # Capture task data and outputs
    for callback in raw_callbacks:
        tasks = await mythic.get_all_tasks(
            mythic_instance,
            callback_display_id=callback["display_id"]
        )
        captured_data["tasks"].extend(tasks)

        for task in tasks:
            outputs = await mythic.get_all_task_output_by_id(
                mythic_instance,
                task["display_id"]
            )
            captured_data["outputs"].extend(outputs)

    # Save to JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(captured_data, f, indent=2)

    print(f"Captured data for {len(captured_data['callbacks'])} callbacks")
    print(f"Saved to {output_file}")

async def get_output(server, token, output_file="outputs.json"):
    """Capture real Mythic data for testing purposes."""

    # Connect and get real data
    mythic_instance = await mythic.login(
        apitoken=token,
        server_ip=server,
        server_port=7443,
        timeout=-1,
        logging_level=logging.CRITICAL,
    )

    output_data = []
    # for output in get_data_streams(mythic_instance):
    #     output_data.extend(output)

    async for output in get_all_task_outputs_async(mythic_instance):
        output_data.append(output)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

def get_output_sync(server, token, output_file="outputs.json"):
    """Capture real Mythic data for testing purposes."""

    # Connect and get real data
    mythic_instance = sync(mythic.login(
        apitoken=token,
        server_ip=server,
        server_port=7443,
        timeout=-1,
        logging_level=logging.CRITICAL,
    ))

    output_data = []
    # for output in get_data_streams(mythic_instance):
    #     output_data.extend(output)

    for output in get_all_task_outputs_sync(mythic_instance):
        output_data.extend(output)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

# Usage
# Get server token and output file from command line or config

if __name__ == "__main__":
    # Example usage - replace with actual server, token, and output file
    mythic_server = sys.argv[1]
    mythic_token = sys.argv[2]
    out_file = sys.argv[3]

    # Call the async function
    asyncio.run(capture_mythic_data(mythic_server, mythic_token, out_file))
