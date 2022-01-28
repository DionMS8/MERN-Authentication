import express from "express";
import morgan from "morgan";
import bodyParser from 'body-parser';
import cors from "cors";
import dotenv from "dotenv";

import connectDB from "./config/db";

// CONFIGURING DOTENV
dotenv.config({
    path: './config/config.env'
})

const app = express()

// CONNECTING TO THE DATABASE
connectDB();


//===[SETTING UP MIDDLEWARE]===========================================================================================//

// CONFIGURING BODY-PARSER
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));

// LOADING ROUTES
import authRouter from './routes/auth.route'
// import userRouter from './routes/user.route'

// DEV LOGGING MIDDLEWARE
// USING THE PROCESS.ENV PROPERTY TO CHECK IF WE ARE IN DEVELOPMENT MODE
// RECALL: PROCESS.ENV RETURNS AN OBJECT FOR THE USER ENVIRONMENT VARIABLES

if (process.env.NODE_ENV === "development") {
    app.use(cors({
        origin: process.env.CLIENT_URL
    }))
    app.use(morgan('dev')) // MORGAN PROVIDES INFORMATION ABOUT HTTP REQUESTS
}


//===[USING ROUTES]===========================================================================================//

app.use('/api', authRouter)
// app.use('/api', userRouter)

app.use((req, res) => {
     res.status(404).json({
         success: false,
         msg: "Page not found"
     })
 })


//===[LISTENING TO PORT]===========================================================================================//

const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
    console.log(`App listening on port ${PORT}`);
});








