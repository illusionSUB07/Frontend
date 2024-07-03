const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const app = express();
const PORT = 4002;
const MAX_RETRIES = 10;
let retries = 0;

// Use CORS to allow cross-origin requests
app.use(cors());

// Use body-parser middleware to parse JSON bodies
app.use(bodyParser.json());

// Create a MySQL connection with retry logic
function createConnection() {
  return mysql.createConnection({
    host: "mysql",
    user: "root",
    password: "1234",
    database: "bookStore",
  });
}

function connectWithRetry() {
  const connection = createConnection();

  connection.connect((err) => {
    if (err) {
      console.error(`Error connecting to MySQL database: ${err.stack}`);
      retries += 1;
      if (retries < MAX_RETRIES) {
        console.log(`Retrying connection (${retries}/${MAX_RETRIES})...`);
        setTimeout(connectWithRetry, 5000); // Retry after 5 seconds
      } else {
        console.error('Max retries reached. Exiting...');
        process.exit(1);
      }
    } else {
      console.log('Connected to MySQL database as id ' + connection.threadId);
      startServer(connection);
    }
  });
}

// JWT authentication middleware
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `http://keycloak:8080/auth/realms/bookStore/protocol/openid-connect/certs`
  }),
  audience: 'react-client',
  issuer: `http://keycloak:8080/auth/realms/bookStore`,
  algorithms: ['RS256']
});

function startServer(connection) {
  // GET route to fetch all books
  app.get('/books', (req, res) => {
    connection.query('SELECT * FROM books', (error, results) => {
      if (error) {
        res.status(500).send(error);
        return;
      }
      res.json(results);
    });
  });

  // POST route to add a new book (admin only)
  app.post('/books', checkJwt, (req, res) => {
    if (!req.auth.realm_access.roles.includes('admin')) {
      return res.status(403).send('Access denied');
    }
    const newBook = req.body; 
    connection.query('INSERT INTO books SET ?', newBook, (error, results) => {
      if (error) {
        res.status(500).send(error);
        return;
      }
      res.status(201).send('Book added successfully');
    });
  });

  // PUT route to update a book (admin only)
  app.put('/books/:id', checkJwt, (req, res) => {
    if (!req.auth.realm_access.roles.includes('admin')) {
      return res.status(403).send('Access denied');
    }
    const { id } = req.params;
    const updatedBook = req.body;
    connection.query('UPDATE books SET ? WHERE id = ?', [updatedBook, id], (error, results) => {
      if (error) {
        res.status(500).send(error);
        return;
      }
      res.send('Book updated successfully');
    });
  });

  // DELETE route to delete a book (admin only)
  app.delete('/books/:id', checkJwt, (req, res) => {
    if (!req.auth.realm_access.roles.includes('admin')) {
      return res.status(403).send('Access denied');
    }
    const { id } = req.params;
    connection.query('DELETE FROM books WHERE id = ?', id, (error, results) => {
      if (error) {
        res.status(500).send(error);
        return;
      }
      res.send('Book deleted successfully');
    });
  });

  // Start the Express server
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Start the connection process with retry logic
connectWithRetry();
