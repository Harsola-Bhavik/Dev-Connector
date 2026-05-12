import React, { Fragment, useState } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import formatDate from '../../utils/formatDate';
import { connect } from 'react-redux';
import { addLike, removeLike, deletePost, editPost } from '../../actions/post';

const PostItem = ({
  addLike,
  removeLike,
  deletePost,
  editPost,
  auth,
  post: { _id, text, name, avatar, user, image, likes, comments, date },
  showActions
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [editText, setEditText] = useState(text);
  const [editImage, setEditImage] = useState(image || '');

  const handleEditSubmit = (e) => {
    e.preventDefault();
    editPost(_id, { text: editText, image: editImage });
    setIsEditing(false);
  };

  return (
    <div className="post-card animated-fade-in">
      <div>
        <Link to={`/profile/${user}`}>
          <img className="round-img" src={avatar} alt="" />
          <h4>{name}</h4>
        </Link>
      </div>
      <div>
        {isEditing ? (
          <form className="form" onSubmit={handleEditSubmit}>
            <textarea
              name="text"
              cols="30"
              rows="3"
              value={editText}
              onChange={(e) => setEditText(e.target.value)}
              required
              className="input-modern"
              style={{ width: '100%', marginBottom: '10px' }}
            />
            <input
              type="text"
              name="image"
              placeholder="Image URL (Optional)"
              value={editImage}
              onChange={(e) => setEditImage(e.target.value)}
              className="input-modern"
              style={{ width: '100%', marginBottom: '10px' }}
            />
            <input type="submit" className="btn btn-primary" value="Save" />
            <button
              type="button"
              className="btn btn-light"
              onClick={() => setIsEditing(false)}
            >
              Cancel
            </button>
          </form>
        ) : (
          <Fragment>
            <p className="my-1">{text}</p>
            {image && (
              <img
                src={image}
                alt="Post Attachment"
                style={{ maxWidth: '100%', marginBottom: '1rem', borderRadius: '10px' }}
              />
            )}
          </Fragment>
        )}
        
        <p className="post-date">Posted on {formatDate(date)}</p>

        {showActions && !isEditing && (
          <Fragment>
            <button
              onClick={() => addLike(_id)}
              type="button"
              className="action-button"
              style={{ marginRight: '0.5rem' }}
            >
              <i className="fas fa-thumbs-up" />{' '}
              <span>{likes.length > 0 && <span>{likes.length}</span>}</span>
            </button>
            <button
              onClick={() => removeLike(_id)}
              type="button"
              className="action-button"
              style={{ marginRight: '0.5rem' }}
            >
              <i className="fas fa-thumbs-down" />
            </button>
            <Link to={`/posts/${_id}`} className="btn btn-primary">
              Discussion{' '}
              {comments.length > 0 && (
                <span className="comment-count">{comments.length}</span>
              )}
            </Link>
          </Fragment>
        )}

        {/* Edit and Delete buttons are now separated from showActions so they are visible on the Discussion page too! */}
        {!isEditing && !auth.loading && auth.user && (user === auth.user._id || user === auth.user.id) && (
          <Fragment>
            <button
              onClick={() => setIsEditing(true)}
              type="button"
              className="action-button"
              style={{ marginLeft: '1rem' }}
            >
              Edit
            </button>
            <button
              onClick={() => deletePost(_id)}
              type="button"
              className="action-button"
              style={{ marginLeft: '0.5rem', color: '#dc3545', borderColor: '#dc3545' }}
            >
              <i className="fas fa-times" />
            </button>
          </Fragment>
        )}
      </div>
    </div>
  );
};

PostItem.defaultProps = {
  showActions: true
};

PostItem.propTypes = {
  post: PropTypes.object.isRequired,
  auth: PropTypes.object.isRequired,
  addLike: PropTypes.func.isRequired,
  removeLike: PropTypes.func.isRequired,
  deletePost: PropTypes.func.isRequired,
  editPost: PropTypes.func.isRequired,
  showActions: PropTypes.bool
};

const mapStateToProps = (state) => ({
  auth: state.auth
});

export default connect(mapStateToProps, { addLike, removeLike, deletePost, editPost })(
  PostItem
);
