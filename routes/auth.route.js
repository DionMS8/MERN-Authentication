//===[IMPORTING ROUTER MODULE FROM THE EXPRESS LIBRARY]====================================================================//

import { Router } from "express";

const router = Router();

//===[LOADING IN CONTROLLERS]===========================================================================================//

import { 
    registerController, 
    activationController, 
    signinController, 
    forgotPasswordController, 
    resetPasswordController 
} from '../controllers/auth.controller'


//===[LOADING IN HELPERS]===============================================================================================//

import { 
    validSign, 
    validLogin, 
    forgotPasswordValidator, 
    resetPasswordValidator 
} from '../helpers/valid'

router.post("/register",
    validSign,
    registerController)

router.post("/login",
    validLogin, 
    signinController)

router.post("/activation", 
activationController)


//===[FORGOT RESET PASSWORDS]===========================================================================================//

router.put('/forgotpassword', forgotPasswordValidator, forgotPasswordController);
router.put('/resetpassword', resetPasswordValidator, resetPasswordController);







