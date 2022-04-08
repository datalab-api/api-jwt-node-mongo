const mongoose = require('mongoose');

const User = mongoose.model(
    "User",
    new mongoose.Schema({
        username:{type:String, unique:true},
        email: String,
        password: String,
        roles: [
            {
                type:mongoose.Schema.Types.ObjectId,
                ref:"Role"
            }
        ]},
        {timestamps: true}
    ).set("toJSON", {
        virtuals: true,
        versionKey: false,
        transform: function (doc, ret) {
            delete ret._id;
            delete ret.password; 
            delete ret.createdAt;
        },
    })
);

module.exports = User;
