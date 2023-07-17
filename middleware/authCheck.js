const jwt = require('jsonwebtoken');

module.exports = (req,res,next)=>{
   try{
    const token =  req.headers.authorization.split(' ')[1];
    // return res.send(token);
    const decode = jwt.verify(token, process.env.SECRET_KEY);
    req.userData = decode
    // return res.json(decode);
    next();
   }catch(error){
    res.status(401).send({
        message:"UnAuthentication error",
        success:false

    })
   }
}