import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { addPost } from '../../actions/post';

const PostForm = ({ addPost }) => {
  const [text, setText] = useState('');
  const [image, setImage] = useState('');

  return (
    <div className='form-card animated-fade-in'>
      <h3 className="large text-primary">Say Something...</h3>
      <form
        className='form my-1'
        onSubmit={e => {
          e.preventDefault();
          addPost({ text, image });
          setText('');
          setImage('');
        }}
      >
        <textarea
          name='text'
          cols='30'
          rows='5'
          placeholder='Create a post'
          value={text}
          onChange={e => setText(e.target.value)}
          required
          className="input-modern"
        />
        <input
          type='text'
          name='image'
          placeholder='Image URL (Optional)'
          value={image}
          onChange={e => setImage(e.target.value)}
          className='my-1 input-modern'
          style={{ width: '100%', padding: '0.4rem' }}
        />
        <input type='submit' className='btn btn-dark my-1' value='Submit' />
      </form>
    </div>
  );
};

PostForm.propTypes = {
  addPost: PropTypes.func.isRequired
};

export default connect(
  null,
  { addPost }
)(PostForm);
