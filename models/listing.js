const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const listingSchema = new Schema({
    year: {
        type: Number,
        required: true
    },

    make: {
        type: String,
        required: true
    },

    model: {
        type: String,
        required: true
    },

    color: {
        type: String,
        required: true
    },

    mileage: {
        type: Number,
        required: true
    },

    accidents: {
        type: Boolean,
        required: true
    },

    price: {
        type: Number,
        required: true
    },

    createdBy: {
        type: String,
        required: true
    },

    photos: {
        type: [String],
        required: true
    },

    highestBidderUsername: {
        type: String,
        required: false 
    },

    highestBid: {
        type: Number,
        required: false, 
        default: 0 
    },

    status: {
        type: String,
        required: true,
        default: 'pending-review'
    }
    
}, {timestamps: true});

const Listing = mongoose.model('Listing', listingSchema);
module.exports = Listing;