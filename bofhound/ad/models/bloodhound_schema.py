import base64
from uuid import UUID

from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundSchema(object):

	def __init__(self, object):
		self.Name = None
		self.SchemaIdGuid = None

		if 'name' in object.keys() and 'schemaidguid' in object.keys():
			self.Name = object.get('name').lower()
			try:
				value = object.get('schemaidguid')
				if '-' in value:
					self.SchemaIdGuid = value.lower()
				else:
					self.SchemaIdGuid = str(UUID(bytes_le=base64.b64decode(value))).lower()
				logger.debug(f"Reading Schema object {ColorScheme.schema}{self.Name}[/]", extra=OBJ_EXTRA_FMT)
			except:
				logger.warning(f"Error base64 decoding SchemaIDGUID attribute on Schema {ColorScheme.schema}{self.Name}[/]", extra=OBJ_EXTRA_FMT)
