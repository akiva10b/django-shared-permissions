import hashlib
import base64
from Crypto import Random
from Crypto.Cipher import AES
from django.conf import settings
import json
from rest_framework import serializers
import logging

if hasattr(settings, 'ENCRYPTED_USER_FIELD_VALIDATION'):
    ENCRYPTED_USER_FIELD_VALIDATION = settings.ENCRYPTED_USER_FIELD_VALIDATION
else:
    ENCRYPTED_USER_FIELD_VALIDATION = ['id']

logger = logging.getLogger(__name__)

def encrypt_get(func):
    methods = ['GET']
    def wrapper(*args, **kwargs):
        context = kwargs.get('context')
        request = context.get('request')

        result = func(*args, **kwargs)
        if request.method in methods:
            ef = EncryptedFieldsBase()
            if hasattr(func.Meta, "encrypted_fields") and request:
                encrypted_fields = getattr(func.Meta, "encrypted_fields")
                data = result.data
                if isinstance(data, dict):
                    encrypted_data = ef.encrypt_return_data(data, encrypted_fields, request.user)
                if isinstance(data, list):
                    encrypted_data = []
                    for d in data:
                        encrypted_data.append(ef.encrypt_return_data(d, encrypted_fields, request.user))
                result.encrypted_data = encrypted_data
            
        return result
    return wrapper

def decrypt(func):
    def wrapper(*args, **kwargs):
        data = kwargs.get("data")
        context = kwargs.get('context')
        if data and hasattr(func.Meta, "encrypted_fields") and context:
            encrypted_fields = getattr(func.Meta, "encrypted_fields")
            request = context.get('request')
            if request:
                encrypted_data = ef.encrypt_return_data(result.data, encrypted_fields, request.user)
                result.encrypted_data = encrypted_data

        result = func(*args, **kwargs)

        ef = EncryptedFieldsBase()
        if hasattr(func.Meta, "encrypted_fields") and context:
            encrypted_fields = getattr(func.Meta, "encrypted_fields")
            request = context.get('request')
            if request:
                data = result.data
                if isinstance(data, dict):
                    encrypted_data = ef.encrypt_return_data(data, encrypted_fields, request.user)
                if isinstance(data, list):
                    encrypted_data = []
                    for d in data:
                        encrypted_data.append(ef.encrypt_return_data(d, encrypted_fields, request.user))
                result.encrypted_data = encrypted_data
            
        return result
    return wrapper

class AESCipher(object):

    def __init__(self, key=settings.URL_AES_SECRET_KEY):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class DecryptFields():
    def __init__(self, *args, **kwargs):
        super(DecryptFields, self).__init__(*args, **kwargs)
        
        if hasattr(self.Meta, "encrypted_fields") and hasattr(self, "initial_data"):
            encrypted_fields = getattr(self.Meta, "encrypted_fields")
            ef = EncryptedFieldsBase()
            context = kwargs.get('context')
            if context and context.get("request"):
                request = context.get("request")
                data = self.initial_data
                if isinstance(data, dict):
                    decypted_data = ef.decrypt_return_data(data, encrypted_fields, request.user)
                if isinstance(data, list):
                    decypted_data = []
                    for d in data:
                        decypted_data.append(ef.decrypt_return_data(d, encrypted_fields, request.user))

                self.initial_data = decypted_data
                
            else:
                if isinstance(self.initial_data, dict):
                    print(1)

class EncryptedFieldsBase(object):
    cipher = AESCipher()

    encypted_data = None

    def encrypt_return_data(self, data, encrypted_fields, user):
        data_keys = data.keys()

        for field in encrypted_fields:
            if data.get(field):
                validation_params = dict()
                for key in encrypted_fields[field]:
                    if key not in data_keys:
                        logger.exception(f"Key {key} is required in order to validate the encrypted field")
                        raise serializers.ValidationError(["Can't encode encryption"])
                    else:
                        validation_params[key] = data[key]
                data[field] = self.get_encryption(data, field, user, validation_params)
        return data


    def decrypt_return_data(self, data, encrypted_fields, user):
        data_keys = data.keys()

        # for key in data_keys:
        #     if key not in encrypted_fields:
        #         logger.exception(f"Key {key} is required in order to validate the encrypted field")
        #         raise serializers.ValidationError(["Can't decode encryption"])

        for field in encrypted_fields:
            if data.get(field):
                validation_params = dict()
                for key in encrypted_fields[field]:
                    if key not in data_keys:
                        logger.exception(f"Key {key} is required in order to validate the encrypted field")
                        raise serializers.ValidationError(["Can't decode encryption"])
                    else:
                        validation_params[key] = data[key]
                data[field] = self.get_decryption(field, data[field], user, validation_params)
        return data
            
    def get_encryption(self, instance_data, field, user=None, params=dict()):
        """
        Encrypt a model field with user data and parameters for permissions sharing
        """
        data = dict()
        if user:
            data["ENCRYPTED_USER_FIELD_VALIDATION"] = {
                        validation_field: str(getattr(user, validation_field)) 
                        for validation_field in ENCRYPTED_USER_FIELD_VALIDATION
                    }
                    
        data[field] = instance_data[field]

        for param_key in params:
            data[param_key] = str(params[param_key])
        return self.cipher.encrypt(json.dumps(data))

    def get_decryption(self, field, hashed_data, user=None, params=dict()):
        """
        Decrypt a json object that and validate its contents against local parameters
        """
        try:
            json_data = self.cipher.decrypt(hashed_data)
        except Exception as e:
            logger.exception(e)
            raise serializers.ValidationError(["Can't decode encryption"])
        data = json.loads(json_data)
        if user:
            for validation_field in ENCRYPTED_USER_FIELD_VALIDATION:
                if str(data["ENCRYPTED_USER_FIELD_VALIDATION"][validation_field]) != str(getattr(user, validation_field)):
                    logger.exception(f"Incorrest validation value for {validation_field} parameter")
                    raise serializers.ValidationError(["Can't decode encryption"])
        
        for param_key in params:
            if str(data[param_key]) != str(params[param_key]):
                logger.exception(f"Incorrest validation value for {param_key} parameter")
                raise serializers.ValidationError(["Can't decode encryption"])
        return data[field]

