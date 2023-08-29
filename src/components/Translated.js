import React from 'react';
import { handleUpClick } from './Text';
import { handleOnChange } from './Text'

export default function Translated() {
      return (
    <div className="mb-3">
      <label for="translatedText" className="form-label"><h3>Translated Text:</h3> </label>
      <textarea className="form-control" id="myBox2" rows="8" value={handleOnChange}></textarea>
    </div>
  )
}
