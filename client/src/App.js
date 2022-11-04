import React from 'react';
import Home from './components/home';
import OtpVerify from './components/otpVerify';
import PhoneInput from './components/phoneInput';
import StepForm from './components/stepform';
import auth from './auth';

function App() {
  if (auth.isAuthenticated()) return <Home />;
  else return <StepForm />;
}

export default App;
