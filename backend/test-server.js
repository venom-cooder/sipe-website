const express = require('express');
const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
    res.send('Hello World! The test server is working.');
});

app.listen(PORT, () => {
    console.log(`✅ Test server is running on http://localhost:${PORT}`);
});