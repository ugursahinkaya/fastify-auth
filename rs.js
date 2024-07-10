rs.initiate({
  _id: "replicaset",
  members: [
    { _id: 0, host: "test1.mongo.db:27018" },
    { _id: 1, host: "test2.mongo.db:27019" },
    { _id: 2, host: "test3.mongo.db:27020" },
  ],
});
