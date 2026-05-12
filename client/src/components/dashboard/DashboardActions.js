import React, { useRef } from 'react';
import { Link } from 'react-router-dom';
import { connect } from 'react-redux';
import { uploadAvatar } from '../../actions/auth';
import PropTypes from 'prop-types';

const DashboardActions = ({ uploadAvatar }) => {
  const fileInputRef = useRef(null);

  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const formData = new FormData();
      formData.append('avatar', file);
      uploadAvatar(formData);
    }
  };

  return (
    <div className='dashboard-actions-grid'>
      <Link to='/edit-profile' className='action-card'>
        <i className='fas fa-user-circle' /> 
        <span>Edit Profile</span>
      </Link>
      <Link to='/add-experience' className='action-card'>
        <i className='fab fa-black-tie' /> 
        <span>Add Experience</span>
      </Link>
      <Link to='/add-education' className='action-card'>
        <i className='fas fa-graduation-cap' /> 
        <span>Add Education</span>
      </Link>
      
      {/* Hidden file input for Avatar Upload */}
      <input 
        type="file" 
        accept="image/*" 
        style={{ display: 'none' }} 
        ref={fileInputRef} 
        onChange={handleAvatarChange}
      />
      <button 
        className='action-card' 
        onClick={() => fileInputRef.current.click()}
        style={{ background: 'transparent', width: '100%' }}
      >
        <i className='fas fa-camera' /> 
        <span>Update Avatar</span>
      </button>
    </div>
  );
};

DashboardActions.propTypes = {
  uploadAvatar: PropTypes.func.isRequired
};

export default connect(null, { uploadAvatar })(DashboardActions);
