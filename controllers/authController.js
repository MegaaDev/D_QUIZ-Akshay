const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const crypto = require("crypto");
const sendEmail = require("./../utils/email");
const axios = require("axios");

const { decode } = require("querystring");

const qs = require("qs");

const dotenv = require("dotenv");

dotenv.config({ path: "./../config.env" });
const createJWTtoken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_FOR_TOKEN, {
    expiresIn: process.env.TOKEN_EXPIRES_IN,
  });
};

const CreateAndSendToken = (user, statusCode, res) => {
  const token = createJWTtoken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),

    httpOnly: true,
  };

  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;
  res.cookie("jwt", token, cookieOptions);

  user.password = undefined;

  // res.status(statusCode).json({
  //   status: "success",
  //   token,
  //   data: {
  //     user,
  //   },
  // });
};

exports.signUp = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      bio: req.body.bio,
      tags: req.body.tags,
      photo: req.body.photo,
    });
    CreateAndSendToken(newUser, 200, res);
    res.status(200).json({
      status: "success",
      data: { newUser },
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Email or Password was not entered!!",
      });
    }
    console.log("working");

    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await user.checkPasswordCorrect(password, user.password))) {
      return res.status(400).json({
        status: "fail",
        message: "User doesn't exist or Password is incorrect!",
      });
    }
    console.log("working");

    CreateAndSendToken(user, 200, res);
    res.status(200).json({
      status: "success",
      data: { user },
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.protect = async (req, res, next) => {
  try {
    {
      let token;

      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer")
      ) {
        token = req.headers.authorization.split(" ")[1];
      } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
      }
      console.log(token);

      if (!token) {
        return res.redirect("/signup");
      }

      const decoded = await promisify(jwt.verify)(
        token,
        process.env.SECRET_FOR_TOKEN
      );
      //This checks whether the user is logged in
      const correctUser = await User.findById(decoded.id);
      if (!correctUser) {
        return res.status(404).json({
          status: "fail",
          message: "Account doesn't exist",
        });
      }

      // if (correctUser.checkPasswordChangedAt(decode.iat)) {
      //   return res.status(404).json({
      //     status: "fail",
      //     message: "Password was changed Try to login with new password",
      //   });
      // }

      req.user = correctUser;
      next();
    }
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.relocate = async (req, res, next) => {
  try {
    {
      let token;

      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer")
      ) {
        token = req.headers.authorization.split(" ")[1];
      } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
      }

      if (!token) {
        return res.redirect("/signup");
      }

      next();
    }
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.isLogged = async (req, res, next) => {
  try {
    let token;

    if (req.cookies.jwt) {
      token = req.cookies.jwt;

      if (!token) {
        return res.redirect("/signup");
      }

      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.SECRET_FOR_TOKEN
      );

      const freshUser = await User.findById(decoded.id);
      if (!freshUser) {
        return next();
      }

      // if (freshUser.checkPasswordChangedAt(decoded.iat)) {
      //   return next();
      // }

      res.locals.user = freshUser;

      return next();
    }
  } catch (err) {
    console.log(err);

    return next();
  }

  next();
};

exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({ status: "success" });
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "failure",
        message: "You dont have permission to perform this action",
      });
    }
    next();
  };
};

exports.forgotPassword = async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).json({
      status: "fail",
      message: "User with that email doesn't exist",
    });
  }
  const resetToken = user.createResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `localhost:6000/api/users/resetPassword/${resetToken}`;
  const message = `Forgot your Password? Change your password at ${resetURL}. If you didnt forget your password, please ignore this`;

  try {
    await sendEmail({
      email: req.body.email,
      subject: "Your password reset token (valid for 10 mins)",
      message,
    });
    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: "fail",
      message: err,
    });
  }
  // res.status(200).json({
  //   status: "success",
  //   message: "hello",
  // });
};
exports.resetPassword = async (req, res) => {
  try {
    const hasedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hasedToken,
      passwordResetTokenExpiresIn: { $gte: Date.now() },
    });

    if (!user) {
      return res.status(404).json({
        status: "failure",
        message: err,
      });
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiresIn = undefined;

    await user.save();

    CreateAndSendToken(user, 200, res);
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.getGoogleOauthURL = (req, res, next) => {
  const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";

  const options = {
    redirect_uri: process.env.GOOGLE_REDIRECT_URL,
    client_id: process.env.CLIENT_ID_GOOGLE_OAUTH,
    access_type: "offline",
    response_type: "code",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ].join(" "),
  };

  const qs = new URLSearchParams(options);

  res.redirect(`${rootUrl}?${qs.toString()}`);
  res.status(200).json({
    status: "success",
  });
};

const getGoogleOauthTokens = async (code) => {
  try {
    const url = "https://oauth2.googleapis.com/token";

    const value = {
      code,
      redirect_uri: process.env.GOOGLE_REDIRECT_URL,
      client_secret: process.env.CLIENT_SECRET_GOOGLE_OAUTH,
      client_id: process.env.CLIENT_ID_GOOGLE_OAUTH,
      grant_type: "authorization_code",
    };

    const res = await axios.post(url, qs.stringify(value), {
      headers: {
        "Content-type": "application/x-www-form-urlencoded",
      },
    });

    return res.data;
  } catch (err) {}
};

const getGoogleUser = async ({ id_token, access_token }) => {
  try {
    const res = await axios.get(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
      {
        header: {
          Authorization: `Bearer ${id_token}`,
        },
      }
    );

    return res.data;
  } catch (err) {
    console.log(err);
  }
};

const findAndUpdateUser = async (query, update, options) => {
  return await User.findOneAndUpdate(query, update, options);
};

exports.googleOauthHandler = async (req, res, next) => {
  try {
    //get the code from querystring
    const code = req.query.code;

    const { id_token, access_token } = await getGoogleOauthTokens(code);

    //get the id and access token with the code
    const googleUser = await getGoogleUser({ id_token, access_token });
    // jwt.decode(id_token);

    //get user with tokens
    if (!googleUser.verified_email) {
      return res.status(403).json({
        status: "fail",
        message: "google account is not verified",
      });
    }
    //upsert the user
    const user = await findAndUpdateUser(
      {
        email: googleUser.email,
      },
      {
        email: googleUser.email,
        name: googleUser.name,
        username: googleUser.email.split("@")[0],
        photo: googleUser.picture,
      },
      {
        upsert: true,
        new: true,
      }
    );
    CreateAndSendToken(user, 200, res);
    res.redirect("/");
  } catch (err) {
    // console.log(err.response);

    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.getDeltaOauthURL = (req, res, next) => {
  const rootUrl = "https://auth.delta.nitt.edu/authorize";
  // console.log("megaad");

  const options = {
    redirect_uri: process.env.DELTA_REDIRECT_URL,
    client_id: process.env.CLIENT_ID_DELTA_OAUTH,
    grant_type: "authorization_code",
    response_type: "code",
    scope: "user",
  };

  // console.log({ options });

  const qs = new URLSearchParams(options);

  // console.log({ qs });
  res.redirect(`${rootUrl}?${qs.toString()}`);
  res.status(200).json({
    status: "success",
  });
};

const getDeltaOauthTokens = async (code) => {
  try {
    const url = "https://auth.delta.nitt.edu/api/oauth/token";

    const value = {
      code,
      redirect_uri: process.env.DELTA_REDIRECT_URL,
      client_secret: process.env.CLIENT_SECRET_DELTA_OAUTH,
      client_id: process.env.CLIENT_ID_DELTA_OAUTH,

      grant_type: "authorization_code",
    };

    const res = await axios.post(url, qs.stringify(value), {
      headers: {
        "Content-type": "application/x-www-form-urlencoded",
      },
    });
    // console.log("heydaddy");s

    return res.data;
  } catch (err) {
    // console.log(err);
  }
};

const getDeltaUser = async ({ access_token }) => {
  try {
    const res = await axios.post(
      `https://auth.delta.nitt.edu/api/resources/user`,
      {},
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );

    return res.data;
  } catch (err) {
    console.log(err);
  }
};

exports.deltaOauthHandler = async (req, res, next) => {
  try {
    //get the code from querystring
    const code = req.query.code;

    const { access_token } = await getDeltaOauthTokens(code);

    //get the id and access token with the code

    const deltaUser = await getDeltaUser({ access_token });

    //get user with tokens
    // if (!deltaUser.verified_email) {
    //   return res.status(403).json({
    //     status: "fail",
    //     message: "delta account is not verified",
    //   });
    // }
    //upsert the user
    const user = await findAndUpdateUser(
      {
        email: deltaUser.email,
      },
      {
        email: deltaUser.email,
        name: deltaUser.name,
        username: deltaUser.email.split("@")[0],
        photo: "/img/users/default-photo.png",
      },
      {
        upsert: true,
        new: true,
      }
    );
    CreateAndSendToken(user, 200, res);
    res.redirect("/");
  } catch (err) {
    console.log(err);

    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};
