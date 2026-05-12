import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { addComment } from '../../actions/post';

const CommentForm = ({ postId, addComment }) => {
  const [text, setText] = useState('');

  return (
    <div className='form-card animated-fade-in'>
      <h3 className="large text-primary">Leave a Comment</h3>
      <form
        className='form my-1'
        onSubmit={(e) => {
          e.preventDefault();
          addComment(postId, { text });
          setText('');
        }}
      >
        <textarea
          name='text'
          cols='30'
          rows='5'
          placeholder='Comment the post'
          value={text}
          onChange={(e) => setText(e.target.value)}
          required
          className="input-modern"
        />
        <input type='submit' className='btn btn-dark my-1' value='Submit' />
      </form>
    </div>
  );
};

CommentForm.propTypes = {
  addComment: PropTypes.func.isRequired
};

export default connect(null, { addComment })(CommentForm);
