const mongoose = require('mongoose');
const Role = mongoose.model(
    "Role",
    new mongoose.Schema({
        name: String
    },
    { timestamps: true }
    ).set("toJSON", {
        virtuals: true,
        versionKey: false,
        transform: function (doc, ret) {
            delete ret._id;
        },
    })
);
module.exports = Role;
