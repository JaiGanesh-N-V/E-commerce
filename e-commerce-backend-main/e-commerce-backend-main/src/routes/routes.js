import express from 'express';
import verifyJWTToken from '../middeleware/auth.js';
import userRouter from '../routes/user.routes.js'


const router = express.Router();

router.use('/user', userRouter);


export { router };
