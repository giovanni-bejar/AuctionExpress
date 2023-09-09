const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    userBids: [
        {
            listingId: {
                type: Schema.Types.ObjectId,
                ref: 'Listing',
                required: false
            },
            bidValue: {
                type: Number,
                required: false
            }
        }
    ],
    userPurchases: [
        {
            listingId: {
                type: Schema.Types.ObjectId,
                ref: 'Listing',
                required: false
            },
            purchaseValue: {
                type: Number,
                required: false
            }
        }
    ],

    userBuyingPower: {
        type: Number,
        required: false,
        default: 0 
    },

    type: {
        type: String,
        required: true,
        default: "user"
    }

}, {timestamps: true});

const User = mongoose.model('User', userSchema);
module.exports = User;
