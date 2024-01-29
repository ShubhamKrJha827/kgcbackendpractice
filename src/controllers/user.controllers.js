import {asyncHandler} from "../utills/asyncHandler.js";
import {ApiError} from "../utills/ApiError.js"

import { ApiResponse } from "../utills/ApiResponse.js";
import { User } from "../model/user.model.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
// seprate use anyway generate referesh and access tokens login and logout etc -
const generateAccessAndRefereshTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
       const refereshToken =  user.generateRefreshToken()

       user.refereshToken = refereshToken
       await user.save({validateBeforeSave: false})

       return {accessToken, refereshToken}
    } catch (error) {
        throw new ApiError(500, "something went wroung while generating referesh and sucess token")
    }

}



const registerUser = asyncHandler(async(req,res) => {
    const {fullName, userName, email, password, locality, city} = req.body;

    if ([fullName,userName,email,password, locality, city].some((field)=>
        field?.trim()=== "")
        ) {
          throw new ApiError(400, "fullname is required")  
    }

    const existedUser = await User.findOne({
        $or: [{userName}, {email}]
    })

    if (existedUser) {
        throw new ApiError(409, "user with email or username already exists")
        
    }

    const user = await User.create({
        fullName,
        email,
        password,
        userName,
        locality, 
        city
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refereshToken"
       )
       if (!createdUser) {
        throw new ApiError(500, "something went wrong while registring a user")
        
       }
       return res.status(201).json(
        new ApiResponse(200, createdUser,"user registred successfully")
       )
    
})

const loginUser = asyncHandler(async(req, res)=>{
    // step-1
        const {email, userName, password} = req.body
        // step-2
            if (!userName && !email) {
            throw new ApiError(400, "username or email is required")
        }
        // step3-
    
        const user = await User.findOne({
            $or: [{userName}, {email}]
        })
        if (!user) {
            throw new ApiError(404, "user does not exist")
            
        }
        // step4-
       const isPasswordValid = await user.isPasswordCorrect(password)
       if (!isPasswordValid) {
        throw new ApiError(401, "password invalid")   
          }
    // step5worktotal-
          const {accessToken, refereshToken} = await generateAccessAndRefereshTokens(user._id)
    
          // step6-
    
         const loggedInUser = await User.findById(user._id).
         select("-password -refereshToken")
    
         const options = {
            httpOnly: true,
            secure: true
         }
         return res
         .status(200)
         .cookie("accessToken", accessToken, options)
         .cookie("refereshToken", refereshToken, options)
    
       // step7-
         .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refereshToken
                },
                "user logged In sucessfully"
    
            )
         )
    
        })

        const logoutUser = asyncHandler(async(req, res)=>{
            await User.findByIdAndUpdate(
                 req.user._id,
                 {
                     $set: {
                         refereshToken: undefined
                     }
                 },
                 {
                     new: true
                 }
             )
             const options = {
                 httpOnly: true,
                 secure: true
              }
              return res
              .status(200)
              .clearCookie("accessToken", options)
              .clearCookie("refereshToken", options)
              .json(new ApiResponse(200, {}, "user logged out"))
     
         })

         const refereshAcessToken = asyncHandler(async(req,res)=>{
            const incomingRefereshToken = req.cookie.refereshToken || req.body.refereshToken
     
            if (!incomingRefereshToken) {
            throw new ApiError(401, "unauthorized request")
             
            }
           try {
             const decodedToken =  jwt.verify(
               incomingRefereshToken,
               process.env.REFRESH_TOKEN_SECRET
              )
       
             const user = await User.findById(decodedToken?._id)
       
             if (user) {
               throw new ApiError(401, "invalid request token")
                
               }
       
               if (incomingRefereshToken !== user?.refereshToken) {
                   throw new ApiError(401, "referesh token is experied or used")
                   
               }
       
               const options = {
                   httpOnly: true,
                   secure: true
               }
               const {accessToken,newRefereshToken} = await generateAccessAndRefereshTokens(user._id)
       
               return res
               .status(200)
               .cookie("accessToken", accessToken, options )
               .cookie("refereshToken", newRefereshToken, options)
               .json(
                   new ApiResponse(
                       200,
                       {accessToken,refereshToken: newRefereshToken},
                       "Access Token refereshed"
                   )
               )
           } catch (error) {
             throw new ApiError(401,error?.message || "invalid referesh Token")
             
           }
         })

         const changeCurrentPassword = asyncHandler(async(req, res) => {
            const {oldPassword, newPassword} = req.body
        
            // if (!(newPassword===confpassword)) {
            //     throw new ApiError(400, "not match new password")
            // }     
            // }
        
            const user = await User.findById(req.user?._id)
            const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
        
            if (!isPasswordCorrect) {
                throw new ApiError(400, "Invalid old password")
            }
        
            user.password = newPassword
            await user.save({validateBeforeSave: false})
            
            console.log("user", user)
            return res
            .status(200)
            .json(new ApiResponse(200, {}, "Password changed successfully"))
        })

        const getCurrentUser = asyncHandler(async(req, res) => {
            return res
            .status(200)
            .json(new ApiResponse(
                200,
                req.user,
                "User fetched successfully"
            ))
        })

        const updateAccountDetails = asyncHandler(async(req, res) => {
            const {fullName, email} = req.body
        
            if (!fullName || !email) {
                throw new ApiError(400, "All fields are required")
            }
        
            const user = await User.findByIdAndUpdate(
                req.user?._id,
                {
                    $set: {
                        fullName: fullName,
                        email: email
                    }
                },
                {new: true}
                
            ).select("-password")
        
            return res
            .status(200)
            .json(new ApiResponse(200, user, "Account details updated successfully"))
        });


export {
    registerUser,
    loginUser,
    logoutUser,
    refereshAcessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails
                           }