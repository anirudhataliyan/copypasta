import React from 'react';
import { handleOnChange } from './Text';
import { handleOnClick } from './Text';

export default function Buttons() {
  return (
      <div className="flex-row align-items-center">
        <button type="button" className="btn btn-primary mt-2" onClick={handleOnClick}>Uppercase</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Lowercase</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Remove Spaces</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Word Count</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Base64</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Button</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Button</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Button</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Button</button>&emsp;
        <button type="button" className="btn btn-primary mt-2">Clear</button>&emsp;

      </div>
  );
}
