//=====[DESIGNING THE USER SCHEMA AND MODEL FOR AUTHENTICATION]=============================================
import { Schema, model } from 'mongoose';

// - THE CRYPTO MODULE PROVIDES CRYPTOGRAPHIC FUNCTIONALITY
import { createHmac } from 'crypto';

// - HMAC => HASHED MESSAGE AUTHENTICATION CODE


//===[DESIGNING THE USER SCHEMA]======================================================================

const userSchema = new Schema(
  {
    email: {
      type: String,
      trim: true,
      required: true,
      unique: true,
      lowercase: true
    },
    name: {
      type: String,
      trim: true,
      required: true
    },
    hashed_password: {
      type: String,
      required: true
    },
    salt: String,
    role: {
      type: String,
      default: 'user'
    },
    resetPasswordLink: {
      data: String,
      default: ''
    }
  },
  {
    timestamps: true
  }
);


//===[VIRTUAL PASSWORD]===========================================================

userSchema
  .virtual('password') // VIRTUAL IMPLIES THAT IT IS NOT STORED IN MONGODB
  .set(function(password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function() {
    return this._password;
  });


//===[METHODS]===================================================================

// - ARROW FUNCTIONS CANNOT BE USED HERE BECAUSE 
// OF THE THIS KEYWORD

userSchema.methods = {

  // GENERATING THE SALT
  makeSalt: function() {
    return Math.round(new Date().valueOf() * Math.random()) + '';
  },

  // ENCRYPTING THE PASSWORD WITH HMAC
  encryptPassword: function(password) {
    if (!password) return '';
    try {
      return createHmac('sha1', this.salt)
        .update(password)
        .digest('hex');
    } catch (err) {
      return '';
    }
  },

  // COMPARING THE PASSWORD ENTERED BY USER 
  // WITH THE HASHED PASSWORD
  authenticate: function(plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  }
};

// EXPORTING THE USER MODEL
export default model('User', userSchema);






