function (user, context, callback) {
  const namespace = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/roles';
  const assignedRoles = (context.authorization || {}).roles;
  const idTokenClaims = context.idToken || {};
  
  idTokenClaims[namespace] = assignedRoles;
  callback(null, user, context);
}