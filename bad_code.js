// test an unsafe SQL query example
const mysql = require('mysql');

function getUser(connection, userId) {
  const sql = "SELECT * FROM users WHERE id = '" + userId + "'";
  connection.query(sql, (error, results) => {
    if (error) throw error;
    console.log(results);
  });
}