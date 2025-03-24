const express= require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoose = require('mongoose');
const authRouter = require('./routers/authRouter')
const eventRouter = require('./routers/eventRoutes');


const app = express();
app.use(cors());
app.use(helmet())
app.use(express.json());
app.use(express.urlencoded({extended: true}));

mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.log(err);
});
app.use('/api/auth',authRouter)
app.use('/api/event',eventRouter)
app.get('/', (req, res) => {
    res.json({message:'Hello World'});
});

app.listen(process.env.PORT, () => {
    console.log('Server is running on port 8000');
})