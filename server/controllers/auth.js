import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
    try {
        // Check if email already exists
        const em = await User.findOne({ email: req.body.email });
        if (em)
            return res.status(409).send({ message: "User with given email already exists" });

        // Hash the password
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);

        // Create a new user
        const newUser = new User({
            ...req.body,
            password: hash,
        });

        // Save the new user
        await newUser.save();
        res.status(200).send("User has been created.");
    } catch (err) {
        next(err);
    }
};

export const login = async (req, res, next) => {
    try {
        // Find user by username
        const user = await User.findOne({ username: req.body.username });
        if (!user) return next(createError(404, "User not found!"));

        // Check password
        const isPasswordCorrect = await bcrypt.compare(
            req.body.password,
            user.password
        );
        if (!isPasswordCorrect)
            return next(createError(400, "Wrong password or username!"));

        // JWT Secret check - Add fallback if process.env.JWT is not defined
        const jwtSecret = process.env.JWT || "fallback_secret_key";
        if (!jwtSecret) {
            return next(createError(500, "JWT secret is missing!"));
        }

        // Create token
        const token = jwt.sign(
            { id: user._id, isAdmin: user.isAdmin },
            jwtSecret,
            { expiresIn: "1h" } // Optional: Token expiry of 1 hour
        );

        const { password, isAdmin, ...otherDetails } = user._doc;

        // Send response with token and user details
        res
            .cookie("access_token", token, {
                httpOnly: true, // Prevents client-side access to the cookie
            })
            .status(200)
            .json({ details: { ...otherDetails }, isAdmin });
    } catch (err) {
        next(err);
    }
};
