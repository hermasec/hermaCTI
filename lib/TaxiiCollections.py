import json
from flask import jsonify
from lib.Database import Database
from lib.STIX import STIX


class TaxiiCollections:
    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')

    def getTaxiiCollections(self):

        data = self.db_manager.find_documents('collections')

        if data:
            return jsonify(data), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
        else:
            collections = []
            collection ={
                        "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
                        "title": "High Value Indicator Collection",
                        "description": "This data collection contains high value IOCs",
                        "can_read": True,
                        "can_write": True,
                        "media_types": [
                            "application/stix+json;version=2.1"
                        ]
                    }
            collections.append(collection)
            self.db_manager.insert_document('collections', collection)
            return jsonify(collections), 200, {'Content-Type': 'application/taxii+json;version=2.1'}

    def get_collection_by_id(self, collection_id):
        query = {'id': {'$eq': collection_id}}
        data = self.db_manager.find_documents('collections', query)

        if data:
            return jsonify(data[0]), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
        else:
            return jsonify({"error": "Collection not found"}), 404, {
                'Content-Type': 'application/taxii+json;version=2.1'}

    def get_collection_objects(self, collection_id):
        check_collection_query = {'id': {'$eq': collection_id}}
        collection = self.db_manager.find_documents('collections', check_collection_query)

        if collection:
            query = {'collection_id': {'$eq': collection_id}}
            stix_objects = self.db_manager.find_documents('stix_objects', query)

            if stix_objects:
                stix_data = {"objects": [obj["stix_object"] for obj in stix_objects]}
                return jsonify(stix_data), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
            else:
                return jsonify({"error": "No objects in this collection"}), 404, {
                    'Content-Type': 'application/taxii+json;version=2.1'}
        else:
            return jsonify({"error": "The API Root or Collection ID are not found, or the client can not write to "
                                     "this objects resource"}), 404, {'Content-Type': 'application/taxii+json;version'
                                                                                      '=2.1'}

    def add_objects_to_collection(self, sha256, collection_id, objects):

        check_collection_query = {'id': {'$eq': collection_id}}
        collection = self.db_manager.find_documents('collections', check_collection_query)

        if collection:
            query = {'sha256': {'$eq': sha256}}
            stix_object = self.db_manager.find_documents('stix_objects', query)
            if stix_object:
                return jsonify({"error": "object already exists"}), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
            else:
                stix = STIX()
                stix_bundle = stix.all_stix_data(objects)
                stix_json = json.loads(stix_bundle.serialize(pretty=True))

                data = {
                    "sha256": sha256,
                    "collection_id": collection_id,
                    "stix_object": stix_json
                }
                self.db_manager.insert_document('stix_objects', data)

                return jsonify(data), 200, {'Content-Type': 'application/taxii+json;version=2.1'}

        else:
            return jsonify({"error": "The API Root or Collection ID are not found, or the client can not write to "
                                     "this objects resource"}), 404, {'Content-Type': 'application/taxii+json;version'
                                                                                      '=2.1'}

    def get_object_by_id(self, collection_id, object_id):
        check_collection_query = {'id': {'$eq': collection_id}}
        collection = self.db_manager.find_documents('collections', check_collection_query)

        if collection:
            query = {'collection_id': collection_id, 'stix_object.id': object_id}
            stix_objects = self.db_manager.find_documents('stix_objects', query)

            if stix_objects:
                return jsonify(stix_objects[0]["stix_object"]), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
            else:
                result = self.db_manager.search_object_id_aggregate('stix_objects', collection_id, object_id)
                if result:
                    matched_object = result[0]['matchedObject']
                    return jsonify(matched_object), 200, {'Content-Type': 'application/taxii+json;version=2.1'}
                else:
                    return jsonify({"error": "No such object is found"}), 404, {
                        'Content-Type': 'application/taxii+json;version=2.1'}

        else:
            return jsonify({"error": "The API Root or Collection ID are not found, or the client can not write to "
                                     "this objects resource"}), 404, {'Content-Type': 'application/taxii+json;version'
                                                                                      '=2.1'}
