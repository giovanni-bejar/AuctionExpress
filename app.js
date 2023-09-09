require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
const Listing = require('./models/listing')
const User = require('./models/user')
const bcrypt = require('bcrypt');
const session = require('express-session')
const multer = require('multer');
const flash = require('connect-flash')
const path = require('path');
const app = express();
const AWS = require('aws-sdk');
const upload = multer({ storage: multer.memoryStorage() });
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const https = require('https');
const fs = require('fs');


app.use(express.json());

// AWS Credentials
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

// AWS bucket
function uploadToS3(file, listingId, callback) {
    const params = {
        Bucket: 'auction-express',
        Key: `listing-images/${listingId}/${file.originalname}`,  // Include listingId in the Key
        Body: file.buffer,
        ACL: 'public-read' 
    };

    s3.upload(params, (err, data) => {
        if (err) {
            return callback(err, null);
        }
        return callback(null, data.Location);
    });
}

// Function to delete an object from S3
function deleteFromS3(listingId, photoUrl, callback) {
    const photoKey = `listing-images/${listingId}/${path.basename(photoUrl)}`;
    const params = {
      Bucket: 'auction-express',
      Key: photoKey
    };
  
    s3.deleteObject(params, function(err, data) {
      if (err) {
        return callback(err);
      }
      return callback(null, data);
    });
  }



// Initialize the HTTPS server
const httpsServer = https.createServer(app);


// mongoDB 
const dbURI = (process.env.dbURI)
mongoose.connect(dbURI)
  .then((result) => {
    console.log('connected!');
    httpsServer.listen(3000, () => {
      console.log('HTTPS Server running on port 3000');
    });
  })
  .catch((err) => {
    console.log(err);
  });


app.set('view engine', 'ejs');
app.use(session({
    secret: '12345',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }  // true only if in production
}));
app.use(flash());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true}));


// logs
app.use(morgan('dev'));


// Function to check whether user is logged in or not.
const requireLogin = (req, res, next) => {
    if (req.session && req.session.user) {
        // User is logged in, proceed to the next middleware
        next();
    } else {
        // User is not logged in, redirect to login page
        res.redirect('/login');
    }
};

// index
app.get('/', async (req, res) => {
  try {
    // Fetch the listings
    const listings = await Listing.find({ status: 'active' }).sort({ createdAt: -1 });


    // Fetch the total number of listings
    const totalNumberListings = await Listing.countDocuments();

    // Get the user from the session
    const user = req.session.user;

    // Render the page and pass the data to the EJS template
    res.render('index', { title: 'Home', listing: listings, user: user, totalNumberListings: totalNumberListings });
  } catch (err) {
    console.log(err);
  }
});

app.get('/add-funds', requireLogin, (req, res) => {
  const user = req.session.user;
  res.render('add-funds', { title: 'Add Funds', user, stripePublicKey: process.env.STRIPE_PUBLIC_KEY });
});


app.post("/payment", async (req, res) => {
  const { stripeToken, userId, amount } = req.body;
  
  // Ensure amount is an integer
  const amountInCents = parseInt(amount, 10) * 100;

  try {
    const charge = await stripe.charges.create({
      amount: amountInCents,
      currency: "usd",
      source: stripeToken,
    });

    await User.findByIdAndUpdate(userId, { $inc: { userBuyingPower: amount }});

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.json({ success: false });
  }
});

// login
app.get('/login', (req, res) => {
    const errorMessage = req.flash('errorMessage');
    res.render('login', {title: 'Login', errorMessage: errorMessage[0]});
});

// signup
app.get('/signup', (req, res) => {
    const errorMessage = req.flash('errorMessage');
    res.render('signup', {title: 'Signup', errorMessage: errorMessage[0]});
});

// create listing
app.get('/create-listing', requireLogin, (req, res) => {
    res.render('create-listing', {title: 'Create Listing'});
});

app.get('/listings', async (req, res) => {
  try {
    const query = { status: 'active' };

    // Year Range
    if (req.query.minYear || req.query.maxYear) {
      query.year = {};
      if (req.query.minYear) query.year.$gte = Number(req.query.minYear);
      if (req.query.maxYear) query.year.$lte = Number(req.query.maxYear);
    }

    // Accidents
    if (req.query.accidents) {
      query.accidents = req.query.accidents === 'yes';
    }

    // Price Range
    if (req.query.minPrice || req.query.maxPrice) {
      query.price = {};
      if (req.query.minPrice) query.price.$gte = Number(req.query.minPrice);
      if (req.query.maxPrice) query.price.$lte = Number(req.query.maxPrice);
    }

    // Color
    if (req.query.color) {
      query.color = req.query.color;
    }

    // Mileage Range
    if (req.query.minMileage || req.query.maxMileage) {
      query.mileage = {};
      if (req.query.minMileage) query.mileage.$gte = Number(req.query.minMileage);
      if (req.query.maxMileage) query.mileage.$lte = Number(req.query.maxMileage);
    }

    const allListings = await Listing.find(query);
    const user = req.session.user;  // Get user from session
    res.format({
      'text/html': function () {
        res.render('allListings', { title: 'All Listings', listing: allListings, user: user });
      },
      'application/json': function () {
        res.json({ listing: allListings });
      },
      'default': function () {
        // log the request and respond with 406
        res.status(406).send('Not Acceptable');
      }
    });
    
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred');
  }
});

  
  

// all listings POST
app.post('/listings', requireLogin, upload.array('photos', 10), async (req, res) => {
    // Create a new listing to get the listingId (You might already have this logic
    const tempListing = new Listing({
        ...req.body,
        createdBy: req.session.user.username  // Set createdBy to the username of the logged-in user
    });
    await tempListing.save();
    const listingId = tempListing._id;

    const uploadPromises = req.files.map((file) => {
        return new Promise((resolve, reject) => {
            uploadToS3(file, listingId, (err, url) => {  // Pass listingId here
                if (err) return reject(err);
                return resolve(url);
            });
        });
    });

    try {
        const photos = await Promise.all(uploadPromises);

        // Update MongoDB with the photos URLs
        const newListingData = {
            ...req.body,
            photos  // Add the photos URLs
        };

        await Listing.findByIdAndUpdate(listingId, newListingData);  // Update the existing listing

        console.log('New listing added');
        res.redirect('/');
    } catch (err) {
        console.log(err);
        res.status(500).send('An error occurred');
    }
});

// login 
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if an account with the given email exists
        const existingUser = await User.findOne({ email: email });
        if (!existingUser) {
            req.flash('errorMessage', 'No account found with this email');
            return res.redirect('/login');
        }

        // Compare the provided password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, existingUser.password);
        if (passwordMatch) {
            req.session.user = existingUser;  // Store user in session
            console.log('Logged in');
            res.redirect('/');
        } else {
            req.flash('errorMessage', 'Incorrect Password');
            return res.redirect('/login');
        }
    } catch (error) {
        console.error(error);
        req.flash('errorMessage', 'An error occurred. Please try again.');
        return res.redirect('/login');
    }
});

app.post('/signup', async (req, res) => {
    const { name, email, username, password } = req.body;

    try {
        // Check if an account with the given email already exists
        const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (existingUser) {
            if (existingUser.email === email) {
                req.flash('errorMessage', 'Account with this email already exists');
            } else {
                req.flash('errorMessage', 'Username is already taken');
            }
            return res.redirect('/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name: name,
            email: email,
            username: username,
            password: hashedPassword
        });

        await user.save();

        // Log the user in automatically by adding their user object to the session
        req.session.user = user;
        console.log('Account created and user logged in!');
        res.redirect('/');
    } catch (error) {
        console.error(error);
        req.flash('errorMessage', 'An error occurred. Please try again.');
        res.status(500).redirect('/signup');
    }
});

const checkActiveListings = async (req, res, next) => {
    const username = req.session.user.username;
    const listings = await Listing.find({ createdBy: username });
    if (listings.length > 0) {
      req.session.activeListings = true;
    } else {
      req.session.activeListings = false;
    }
    next();
  };
  
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        }
        res.redirect('/');
    });
});

app.get('/account-settings', requireLogin, checkActiveListings, (req, res) => {
    const user = req.session.user;
    res.render('account-settings', { title: 'Account Settings', user, activeListings: req.session.activeListings });
  });
  

app.post('/account-settings', requireLogin, async (req, res) => {
    const { username, email, currentPassword, newPassword } = req.body;
    const user = req.session.user;
  
    try {
      const existingUser = await User.findById(user._id);
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, existingUser.password);
  
      if (!isCurrentPasswordValid) {
        // Handle invalid current password
        req.flash('errorMessage', 'Current password is incorrect');
        return res.redirect('/account-settings');
      }
  
      if (newPassword) {
        // Update password if newPassword is provided
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        existingUser.password = hashedPassword;
      }
  
      // Update other details
      existingUser.username = username;
      existingUser.email = email;
  
      await existingUser.save();
  
      req.session.user = existingUser; // Update session
      req.flash('successMessage', 'Account settings updated');
      res.redirect('/account-settings');
    } catch (error) {
      console.error(error);
      req.flash('errorMessage', 'An error occurred. Please try again.');
      res.redirect('/account-settings');
    }
  });

app.post('/account-settings/delete', requireLogin, async (req, res) => {
  const user = req.session.user;

  try {
    // Delete the user account from the database
    await User.findByIdAndDelete(user._id);

    // Destroy the session to log the user out
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
      }
      res.redirect('/');
    });
  } catch (error) {
    console.error(error);
    req.flash('errorMessage', 'An error occurred while deleting the account. Please try again.');
    res.redirect('/account-settings');
  }
});

  
// Display user listings
app.get('/user-listings', requireLogin, async (req, res) => {
  try {
    const username = req.session.user.username;
    let sortQuery = { status: 1 };  // Default sort by status in ascending order

    const sortBy = req.query.sortBy;
    if (sortBy === 'highestBid') {
      sortQuery = { highestBid: -1 };
    } else if (sortBy === 'lowestBid') {
      sortQuery = { highestBid: 1 };
    } else if (sortBy === 'newest') {
      sortQuery = { createdAt: -1 };
    } else if (sortBy === 'oldest') {
      sortQuery = { createdAt: 1 };
    }

    const listings = await Listing.find({ createdBy: username }).sort(sortQuery);
    res.render('user-listings', { title: 'My Listings', listings: listings, user: req.session.user });
  } catch (err) {
    console.log(err);
    res.status(500).send('An error occurred');
  }
});


// Edit listing GET
app.get('/edit-listing/:id', requireLogin, async (req, res) => {
  const listingId = req.params.id;
  const currentUser = req.session.user.username; // Get username of the logged-in user

  try {
      const listing = await Listing.findById(listingId);

      if (listing.createdBy === currentUser || currentUser.type === "admin" ) {  // Check if the listing was created by the current user
          res.render('edit-listing', { title: 'Edit Listing', listing: listing, user: req.session.user });
      } else {
          res.status(403).send('Access Denied'); // 403 Forbidden
      }
  } catch (err) {
      console.log(err);
      res.status(500).send('An error occurred');
  }
});

app.get('/my-bids', requireLogin, async (req, res) => {
  const username = req.session.user.username; // Get the username from the session

  try {
    // Fetch the user from MongoDB by their username
    const user = await User.findOne({ username: username });

    if (!user) {
      // Handle the case where the user is not found (though this should not happen)
      return res.status(404).send('User not found');
    }

    // Extract the user's bids from the user document
    const userBids = user.userBids;

    // Populate the listing details for each bid
    for (let i = 0; i < userBids.length; i++) {
      userBids[i].listingId = await Listing.findById(userBids[i].listingId);
    }

    // Render the view and pass the user and userBids
    res.render('userBids', { title: 'My Bids', user: user, userBids: userBids,  errorMessage: req.flash('errorMessage'), successMessage: req.flash('successMessage') });
    
  } catch (err) {
    console.log(err);
    res.status(500).send('An error occurred');
  }
});

app.get('/my-purchases', requireLogin, async (req, res) => {
  const username = req.session.user.username; // Get the username from the session

  try {
    // Fetch the user from MongoDB by their username
    const user = await User.findOne({ username: username });

    if (!user) {
      // Handle the case where the user is not found (though this should not happen)
      return res.status(404).send('User not found');
    }

    // Extract the user's purchases from the user document
    const userPurchases = user.userPurchases;

    // Populate the listing details for each purchase
    for (let i = 0; i < userPurchases.length; i++) {
      userPurchases[i].listingId = await Listing.findById(userPurchases[i].listingId);
    }

    // Render the view and pass the user and userPurchases
    res.render('userPurchases', { title: 'My Purchases', user: user, userPurchases: userPurchases });
    
  } catch (err) {
    console.log(err);
    res.status(500).send('An error occurred');
  }
});


app.post('/accept-bid/:id', requireLogin, async (req, res) => {
  const listingId = req.params.id;
  const currentUser = req.session.user.username;

  try {
    const listing = await Listing.findById(listingId);

    // Check if the listing was created by the current user
    if (listing.createdBy !== currentUser) {
      return res.status(403).send('Access Denied'); // 403 Forbidden
    }

    // Get the highestBid and highestBidderUsername from the listing
    const { highestBid, highestBidderUsername } = listing;

    // Fetch the bidder and owner details from the database
    const highestBidder = await User.findOne({ username: highestBidderUsername });
    const owner = await User.findOne({ username: currentUser });

    // Check if the highest bidder has enough buying power
    if (highestBidder.userBuyingPower < highestBid) {
      req.flash('errorMessage', 'The highest bidder does not have enough buying power.');
      return res.redirect('/user-listings');
    }

    // Subtract bid amount from the highest bidder's buying power
    await User.findByIdAndUpdate(highestBidder._id, { $inc: { userBuyingPower: -highestBid } });

    // Add bid amount to the listing owner's buying power
    await User.findByIdAndUpdate(owner._id, { $inc: { userBuyingPower: highestBid } });

    // Update the bidder's purchases
    await User.updateOne(
      { _id: highestBidder._id },
      { $push: { userPurchases: { listingId: listing._id, purchaseValue: highestBid } } }
    );

    // Remove the accepted bid from the highest bidder's bids
    await User.updateOne(
      { _id: highestBidder._id },
      { $pull: { userBids: { listingId: listing._id } } }  // Using $pull to remove the bid
    );

    // Update the listing status to 'sold'
    await Listing.findByIdAndUpdate(listingId, { status: 'sold' });

    req.flash('successMessage', 'Bid accepted successfully.');
    res.redirect('/user-listings');

  } catch (err) {
    console.log(err);
    req.flash('errorMessage', 'An error occurred while accepting the bid.');
    res.redirect('/user-listings');
  }
});

// Delete listing POST
app.post('/delete-listing/:id', requireLogin, async (req, res) => {
    const listingId = req.params.id;
    try {
        const listing = await Listing.findById(listingId);

        // Remove images from S3
        if (listing.photos && listing.photos.length > 0) {
            const deleteParams = {
                Bucket: 'auction-express',
                Delete: {
                    Objects: listing.photos.map(photoUrl => {
                        const key = photoUrl.split('/').slice(-3).join('/'); // Extract the last 3 segments of the URL
                        return { Key: key };
                    })
                }
            };

            s3.deleteObjects(deleteParams, (err, data) => {
                if (err) {
                    console.log(err);
                    return;
                }
                console.log(`Successfully deleted images for listing ${listingId}`);
            });
        }

        // Remove listing from MongoDB
        await Listing.findByIdAndDelete(listingId);
        res.redirect('/user-listings');
    } catch (err) {
        console.log(err);
        res.status(500).send('An error occurred');
    }
});

// Update listing POST route
app.post('/update-listing/:id', requireLogin, upload.array('newPhotos', 8), async (req, res) => {
  const listingId = req.params.id;
  const currentUser = req.session.user.username; // Get username of the logged-in user

  try {
      const listing = await Listing.findById(listingId);

      // Check if the listing was created by the current user
      if (listing.createdBy !== currentUser) {
          return res.status(403).send('Access Denied'); // 403 Forbidden
      }

      // Handle new photos
      const uploadPromises = req.files.map((file) => {
          return new Promise((resolve, reject) => {
              uploadToS3(file, listingId, (err, url) => {
                  if (err) return reject(err);
                  return resolve(url);
              });
          });
      });
      const newPhotos = await Promise.all(uploadPromises);

      // Handle deleted photos
      const deletedPhotos = req.body.deletedPhotos ? JSON.parse(req.body.deletedPhotos) : [];

      // Update MongoDB
      const updatedPhotos = listing.photos.filter(photo => !deletedPhotos.includes(photo)).concat(newPhotos);

      await Listing.findByIdAndUpdate(listingId, { ...req.body, photos: updatedPhotos });

      // Delete photos from S3
      const deletePromises = deletedPhotos.map((photoUrl) => {
          return new Promise((resolve, reject) => {
              deleteFromS3(listingId, photoUrl, (err, data) => {
                  if (err) return reject(err);
                  return resolve(data);
              });
          });
      });
      await Promise.all(deletePromises);

      res.redirect('/user-listings');
  } catch (err) {
      console.log(err);
      res.status(500).send('An error occurred');
  }
});

app.post('/bid/:id', requireLogin, async (req, res) => {
  const listingId = req.params.id;
  const bidAmount = req.body.bidAmount;
  const username = req.session.user.username;

  try {
    // Fetch the listing from the database
    const listing = await Listing.findById(listingId);

    // Prevent the owner from bidding on their own listing
    if (listing.createdBy === username) {
      req.flash('errorMessage', 'You cannot bid on your own listing.');
      return res.redirect(`/listing/${listingId}`);
    }

    // Fetch the user's details from the database
    const user = await User.findOne({ username: username });

    // Check if the user has enough buying power to place the bid
    if (user.userBuyingPower < bidAmount) {
      req.flash('errorMessage', 'Sorry, you do not have enough buying power.');
      return res.redirect(`/listing/${listingId}`);
    }

    // Check if the new bid amount is higher than the current highest bid
    if (bidAmount > listing.highestBid) {
      await Listing.findByIdAndUpdate(listingId, {
        highestBid: bidAmount,
        highestBidderUsername: username,
      });

      // Update the user's bids in the database
      await User.updateOne(
        { username: username },
        { $push: { userBids: { listingId: listingId, bidValue: bidAmount } } }
      );

      // Flash a success message and redirect back to the listing
      req.flash('successMessage', 'Your bid was successful.');
      return res.redirect(`/listing/${listingId}`);
    } else {
      // Flash an error message and redirect back to the listing
      req.flash('errorMessage', 'Your bid must be higher than the current highest bid.');
      return res.redirect(`/listing/${listingId}`);
    }
  } catch (err) {
    console.log(err);
    // Flash an error message and redirect back to the listing in case of an exception
    req.flash('errorMessage', 'An error occurred while placing the bid.');
    return res.redirect(`/listing/${listingId}`);
  }
});





app.post('/buy-it-now/:id', requireLogin, async (req, res) => {
  const listingId = req.params.id;
  const username = req.session.user.username;

  try {
    const listing = await Listing.findById(listingId);

    if (listing.createdBy === username) {
      req.flash('errorMessage', 'You cannot buy your own listing.');
      return res.redirect('back');
    }

    // Fetch the user's current buying power from the database
    const user = await User.findOne({ username: username });

    if (user.userBuyingPower * 10 < listing.price) {
      req.flash('errorMessage', 'Sorry, you do not have enough buying power');
      return res.redirect('back'); // Redirect to the previous page
    }

    // Update the user's purchases
    await User.updateOne(
      { username: username },
      { $push: { userPurchases: { listingId: listingId, purchaseValue: listing.price } } }
    );

    // Update the listing status to "Sold"
    await Listing.findByIdAndUpdate(listingId, { status: 'sold' });

    res.redirect(`/`);
  } catch (err) {
    console.log(err);
    req.flash('errorMessage', 'An error occurred');
    res.redirect('back'); // Redirect to the previous page
  }
});




app.post('/cancel-bid/:id', requireLogin, async (req, res) => {
  const bidId = req.params.id;
  const username = req.session.user.username;

  try {
    // Find the user's bid
    const user = await User.findOne({ username: username });
    const bid = user.userBids.find(bid => bid._id.toString() === bidId);

    if (!bid) {
        req.flash('errorMessage', 'Bid not found.');
        return res.redirect('/my-bids');
    }

    // Remove the bid from the user's bids
    await User.updateOne(
        { username: username },
        { $pull: { userBids: { _id: bid._id } } }
    );

    // Update the highest bid for the listing if necessary
    const listing = await Listing.findById(bid.listingId);
    if (listing.highestBid === bid.bidValue && listing.highestBidderUsername === username) {
        const newHighestBid = 0;  // Reset the highest bid to 0
        await Listing.findByIdAndUpdate(bid.listingId, {
            highestBid: newHighestBid,
            highestBidderUsername: null
        });
    }

    req.flash('successMessage', 'Bid successfully canceled.');
    res.redirect('/my-bids');  // Redirect to the home page or wherever appropriate
  } catch (err) {
    console.log(err);
    req.flash('errorMessage', 'An error occurred while canceling the bid.');
    res.redirect('/my-bids');
  }
});


app.get('/listing/:id', async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).render('404');
  }
  
  const listingId = req.params.id;
  const user = req.session.user;  // Get user from session
  try {
    const listing = await Listing.findById(listingId);

    // New logic to restrict "pending" listings to their owner
    if (listing.status === 'pending') {
      if (!user || user.username !== listing.createdBy) {
        return res.status(403).send('You do not have permission to view this listing.');
      }
    }

    res.render('listing', {
      title: 'Listing Details',
      ...listing._doc,
      user: user,
      errorMessage: req.flash('errorMessage'),
      successMessage: req.flash('successMessage')
    });
  } catch (err) {
    console.log(err);
    res.status(500).send('An error occurred');
  }
});


// 404 route
app.use((req, res) => {
    res.status(400).render('404');
});
