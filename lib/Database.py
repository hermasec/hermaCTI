from pymongo import MongoClient
import pymongo


class Database:
    def __init__(self, host='localhost', port=27017, database_name='mydatabase'):
        self.client = MongoClient(host, port)
        self.db = self.client[database_name]

    def insert_document(self, collection_name, document):
        collection = self.db[collection_name]
        collection.insert_one(document.copy())

    def update_document(self, collection_name, filter_criteria, update_operation):
        collection = self.db[collection_name]
        collection.update_one(filter_criteria, update_operation)

    def find_documents(self, collection_name, query=None):
        collection = self.db[collection_name]
        cursor = collection.find(query, projection={'_id': 0}) if query else collection.find(projection={'_id': 0})
        return list(cursor)

    def find_and_sort_documents(self, collection_name, sort_field, limit):
        collection = self.db[collection_name]
        cursor = collection.find().sort(sort_field, pymongo.DESCENDING).limit(limit)
        return list(cursor)

    def search_object_id_aggregate(self, collection_name, collection_id, object_id):
        collection = self.db[collection_name]
        pipeline = [
            {
                '$match': {
                    'collection_id': collection_id
                }
            },
            {
                '$unwind': '$stix_object.objects'
            },
            {
                '$match': {
                    'stix_object.objects.id': object_id
                }
            },
            {
                '$project': {
                    '_id': 0,
                    'matchedObject': '$stix_object.objects'
                }
            }
        ]

        result = list(collection.aggregate(pipeline))

        return result



    def get_scans_per_day(self, collection_name):
        collection = self.db[collection_name]
        pipeline = [
            {
                '$group': {
                    '_id': {
                        '$dateToString': {
                            'format': '%Y-%m-%d',
                            'date': '$scan_date'
                        }
                    },
                    'count': {'$sum': 1}
                }
            },
            {
                '$sort': {'_id': -1}  # Sort dates in descending order
            },
            {
                '$project': {
                    '_id': 0,
                    'date': '$_id',
                    'count': 1
                }
            }
        ]

        # Execute the aggregation pipeline
        result = list(collection.aggregate(pipeline))
        return result

    def __del__(self):
        self.client.close()
