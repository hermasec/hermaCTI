from pymongo import MongoClient
import pymongo

class Database:
    def __init__(self, host='localhost', port=27017, database_name='mydatabase'):
        self.client = MongoClient(host, port)
        self.db = self.client[database_name]

    def insert_document(self, collection_name, document):
        collection = self.db[collection_name]
        result = collection.insert_one(document)
        return result.inserted_id

    def update_document(self, collection_name ,filter_criteria, update_operation):
        result = collection_name.update_one(filter_criteria, update_operation)

    def find_documents(self, collection_name, query=None):
        collection = self.db[collection_name]
        cursor = collection.find(query) if query else collection.find()
        return list(cursor)
    
    def find_and_sort_documents(self, collection_name , sort_field , limit):
        collection = self.db[collection_name]
        cursor = collection.find().sort(sort_field, pymongo.DESCENDING).limit(limit)
        return list(cursor)

    def __del__(self):
        self.client.close()