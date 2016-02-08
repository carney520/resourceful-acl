// add property:
//   allowed =>  indicated user can access the resource
//   denied  =>  access denied
//   not_matched => the request path not matched any resource
// add method:
//   as(role)   => useful for checking role inheritance
//
module.exports = function(chai,_){
  var Assertion = chai.Assertion;

  chai.acl = {};

  chai.acl.check_status = function(actual,status){
    return actual.status === status;
  };

  var check_status_property_wrapper = function(status){
    return function(){
      var actual = this._obj;
      this.assert(chai.acl.check_status(actual,status),
          "expect " + JSON.stringify(actual) + " to be #{exp}" ,
          "expect " + JSON.stringify(actual) + " not to be #{exp}",
          status,
          actual.status
          );
    };
  };

  //add Properties
  Assertion.addProperty('allowed',check_status_property_wrapper('allowed'));
  Assertion.addProperty('denied', check_status_property_wrapper('denied'));
  Assertion.addProperty('non_match',check_status_property_wrapper('not_matched'));

  chai.acl.check_role = function(actual,rolename){
    return actual.role === rolename;
  };

  Assertion.addMethod('as',function(rolename){
    var actual = this._obj;
    this.assert(chai.acl.check_role(actual,rolename),
        "expect role is #{exp},but actually is #{act}",
        "expect role not #{exp},but actually is #{act}",
        rolename,
        actual.role
        );
  });

};
