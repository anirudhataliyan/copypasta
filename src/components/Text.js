import React, { useState } from 'react';

export default function Text(props){
  const handleUpClick = () => {
    let newText = text.toUpperCase();
    setText(newText);
  }
  const handleOnChange = (event) => {
    setText(event.target.value);
  }

    const [text, setText] = useState("Enter text here: ");
  return (
    <div className="mb-3">
      <label htmlFor="textToBeTranslated" className="form-label">
        <h3>Enter something to work on:</h3>
      </label>
      <textarea className="form-control" value={text} id="myBox" rows="8" onChange={handleOnChange}></textarea>
    </div>
  );
}
