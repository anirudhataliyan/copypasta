import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Text from './components/Text';
import Translated from './components/Translated';
import Buttons from './components/Buttons';

function App() {
  return (
    <>
      <div className='container'> 
      <Navbar title="Text-Utils" about="About Me"/>
        <Text /> 
        <Buttons />
        &nbsp; 
        <Translated /> 
      </div>
    </>
  );
}

export default App;
