function isAuthenticated(role) {
    return (req, res, next) => {
      if (req.session.user) {
        // Check if user has the required role or if no specific role is needed
        if (!role || req.session.user.role === role) {
          return next();
        } else {
          // User is logged in but does not have the right role
          return res.redirect("/unauthorized"); // or another relevant page
        }
      } else {
        // User is not authenticated
        res.redirect("/login");
      }
    };
  }
  
  module.exports = isAuthenticated;
  